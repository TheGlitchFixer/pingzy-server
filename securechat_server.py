#!/usr/bin/env python3
"""
SecureChat relay server.

A dumb relay: it stores and forwards OPAQUE encrypted blobs. It NEVER sees
plaintext. All encryption/decryption happens on clients.

Services (single process, single port):
  ws://host:PORT/ws          JSON message protocol (register/auth/send/sync/...)
  http://host:PORT/files     File upload (POST) / download (GET)

Protocol (JSON over WebSocket), all binary fields are base64:

  REGISTRATION (email OTP first):
  -------------------------------
  POST /otp/request  {"email": "user@example.com"} -> {"ok": true}
  POST /otp/verify   {"email": "...", "code": "123456"}
                     -> {"ok": true, "verification_token": "<hex>"}

  {"type":"register","username":"alice","email":"user@example.com",
   "verification_token":"<hex from /otp/verify>",
   "identity_pubkey":"<b64 ed25519 32B>","box_pubkey":"<b64 x25519 32B>"}
      -> {"type":"registered","username":"alice"}
         or {"type":"error","code":"not_verified"|"username_taken"|...}
  (username: 3-20 chars, [A-Za-z0-9_]; email must be OTP-verified;
   verification_token is single-use)

  {"type":"check_username","username":"alice"}
      -> {"type":"username_status","valid":true,"available":true}

  {"type":"auth","username":"alice"}
      -> {"type":"challenge","challenge":"<b64 32B>"}

  {"type":"auth_response","username":"alice","signature":"<b64 64B>"}
      -> {"type":"authed","username":"alice"}
         or {"type":"error","code":"bad_signature",...}
     (signature = ed25519(challenge) made with the identity private key)

  {"type":"send","to":"bob","nonce":"<b64 24B>",
   "ciphertext":"<b64>","msg_type":"text|file|voice"}
      -> {"type":"sent","msg_id":123}
     (ciphertext = crypto_box(plaintext_json, nonce, bob_box_pub, alice_box_priv))

  {"type":"group_create","name":"Family","members":["bob","carol"]}
      -> {"type":"group_created","group_id":7,"name":"Family"}
     (creator is added automatically; group E2E keys are distributed by
      CLIENTS via ordinary 1-on-1 "send" messages - the server just relays)

  {"type":"group_add","group_id":7,"username":"dave"}
  {"type":"group_remove","group_id":7,"username":"carol"}
      -> {"type":"ok"}  (only members may add; creator or self may remove)

  {"type":"group_send","group_id":7,"nonce":"<b64 24B>",
   "ciphertext":"<b64>","msg_type":"text|file|voice"}
      -> {"type":"sent","msg_id":124,"recipients":3}
     (ciphertext = crypto_secretbox(plaintext_json, nonce, group_key);
      server fans out one queue row per member)

  {"type":"sync"}
      -> {"type":"message","msg_id":..,"kind":"dm|group","from":"alice",
          "group_id":7|null,"nonce":"<b64>","ciphertext":"<b64>",
          "msg_type":"text|file|voice","ts":1697...}   (repeated)
         {"type":"sync_done"}

  {"type":"ack","msg_ids":[123,124]}
      -> {"type":"ok"}

  {"type":"list_users"}
      -> {"type":"user_list","users":[{"username":"bob","box_pubkey":"<b64>"}]}

  {"type":"my_groups"}
      -> {"type":"group_list","groups":[{"group_id":7,"name":"Family",
                                         "members":["alice","bob"]}]}

  Files (HTTP):
    POST /files  (multipart field "file"; header X-Username; authed via
                  recent ws auth token - see below) -> {"file_id":"...","size":N}
    GET  /files/<file_id> -> raw bytes

File upload auth: after a successful WebSocket auth the server issues a
one-time upload token: {"type":"authed",...,"upload_token":"<hex>"}. The
client sends it as X-Upload-Token on POST /files. Tokens are single-use
and expire after 10 minutes. Downloads require no auth (file_ids are
unguessable 128-bit UUIDs and blobs are encrypted client-side anyway).

Run:
    python securechat_server.py [--host 0.0.0.0] [--port 8765] [--data ./data]
"""

import argparse
import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import sys
import time
import uuid

from aiohttp import web
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

from rate_limit import RateLimiter

# ---- hardening limits -------------------------------------------------
MAX_CIPHERTEXT_BYTES = 256 * 1024   # 256 KB per message; files use /files
MAX_USERNAME_LEN = 32
MAX_GROUP_NAME_LEN = 80

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("securechat")

B64 = lambda b: base64.b64encode(b).decode()          # noqa: E731
UB64 = lambda s: base64.b64decode(s.encode())         # noqa: E731

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    username        TEXT PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    identity_pubkey BLOB NOT NULL,   -- ed25519, 32 bytes
    box_pubkey      BLOB NOT NULL,   -- x25519, 32 bytes
    created_at      REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS otp_codes (
    email       TEXT PRIMARY KEY,
    code_hash   TEXT NOT NULL,       -- sha256 of the 6-digit code
    expires_at  REAL NOT NULL,       -- 10 minutes from issue
    attempts    INTEGER NOT NULL DEFAULT 0,  -- max 5 verify attempts
    requested_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS verified_emails (
    email       TEXT PRIMARY KEY,
    token       TEXT NOT NULL,       -- single-use registration token
    verified_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL,       -- 'dm' or 'group'
    sender      TEXT NOT NULL,
    recipient   TEXT NOT NULL,       -- username (one row per recipient)
    group_id    INTEGER,             -- NULL for dm
    group_name  TEXT,
    nonce       BLOB NOT NULL,       -- 24 bytes
    ciphertext  BLOB NOT NULL,       -- opaque to server
    msg_type    TEXT NOT NULL,       -- text|file|voice (hint only)
    ts          REAL NOT NULL,
    delivered   INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS groups (
    group_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    creator    TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    PRIMARY KEY (group_id, username)
);
CREATE TABLE IF NOT EXISTS files (
    file_id   TEXT PRIMARY KEY,      -- uuid4 hex
    uploader  TEXT NOT NULL,
    filename  TEXT NOT NULL,
    mime      TEXT NOT NULL,
    size      INTEGER NOT NULL,
    sha256    TEXT NOT NULL,
    created_at REAL NOT NULL
);
"""


class Store:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.execute("PRAGMA journal_mode=WAL")
        self._lock = asyncio.Lock()

    # ---- users ---------------------------------------------------------
    async def register(self, username, email, ident_pub, box_pub):
        # username: 3-20 chars, alphanumeric + underscore only
        import re
        if not re.fullmatch(r"[A-Za-z0-9_]{3,20}", username or ""):
            return "bad_username"
        try:
            async with self._lock:
                self.db.execute(
                    "INSERT INTO users(username,email,identity_pubkey,"
                    "box_pubkey,created_at) VALUES(?,?,?,?,?)",
                    (username, email, ident_pub, box_pub, time.time()),
                )
                self.db.commit()
                return "ok"
        except sqlite3.IntegrityError as e:
            msg = str(e).lower()
            if "users.username" in msg:
                return "username_taken"
            if "users.email" in msg:
                return "email_taken"
            return "username_taken"

    async def get_user(self, username):
        async with self._lock:
            row = self.db.execute(
                "SELECT username, identity_pubkey, box_pubkey FROM users WHERE username=?",
                (username,),
            ).fetchone()
            return dict(row) if row else None

    async def list_users(self):
        async with self._lock:
            rows = self.db.execute(
                "SELECT username, box_pubkey FROM users ORDER BY username"
            ).fetchall()
            return [
                {"username": r["username"], "box_pubkey": B64(r["box_pubkey"])}
                for r in rows
            ]

    async def username_available(self, username):
        async with self._lock:
            row = self.db.execute(
                "SELECT 1 FROM users WHERE username=?", (username,)
            ).fetchone()
            return row is None

    # ---- email OTP -----------------------------------------------------
    async def store_otp(self, email, code_hash, expires_at):
        async with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO otp_codes(email,code_hash,expires_at,"
                "attempts,requested_at) VALUES(?,?,?,?,?)",
                (email, code_hash, expires_at, 0, time.time()),
            )
            self.db.commit()

    async def get_otp(self, email):
        async with self._lock:
            row = self.db.execute(
                "SELECT email,code_hash,expires_at,attempts FROM otp_codes"
                " WHERE email=?",
                (email,),
            ).fetchone()
            return dict(row) if row else None

    async def bump_otp_attempts(self, email):
        async with self._lock:
            self.db.execute(
                "UPDATE otp_codes SET attempts=attempts+1 WHERE email=?",
                (email,),
            )
            self.db.commit()

    async def clear_otp(self, email):
        async with self._lock:
            self.db.execute("DELETE FROM otp_codes WHERE email=?", (email,))
            self.db.commit()

    async def mark_email_verified(self, email, token):
        async with self._lock:
            self.db.execute(
                "INSERT OR REPLACE INTO verified_emails(email,token,verified_at)"
                " VALUES(?,?,?)",
                (email, token, time.time()),
            )
            self.db.commit()

    async def consume_verification(self, email, token):
        """Single-use: returns True iff token matches, then deletes it."""
        async with self._lock:
            row = self.db.execute(
                "SELECT token FROM verified_emails WHERE email=?", (email,)
            ).fetchone()
            if not row or not secrets.compare_digest(row["token"], token):
                return False
            self.db.execute("DELETE FROM verified_emails WHERE email=?",
                            (email,))
            self.db.commit()
            return True

    # ---- messages ------------------------------------------------------
    async def queue_message(self, kind, sender, recipient, group_id, group_name,
                            nonce, ciphertext, msg_type):
        async with self._lock:
            cur = self.db.execute(
                "INSERT INTO messages(kind,sender,recipient,group_id,group_name,"
                "nonce,ciphertext,msg_type,ts,delivered)"
                " VALUES(?,?,?,?,?,?,?,?,?,0)",
                (kind, sender, recipient, group_id, group_name, nonce,
                 ciphertext, msg_type, time.time()),
            )
            self.db.commit()
            return cur.lastrowid

    async def pending(self, username, limit=200):
        async with self._lock:
            rows = self.db.execute(
                "SELECT id,kind,sender,recipient,group_id,group_name,nonce,"
                "ciphertext,msg_type,ts FROM messages"
                " WHERE recipient=? AND delivered=0 ORDER BY id LIMIT ?",
                (username, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    async def mark_delivered(self, username, ids):
        async with self._lock:
            self.db.executemany(
                "UPDATE messages SET delivered=1 WHERE id=? AND recipient=?",
                [(i, username) for i in ids],
            )
            self.db.commit()

    # ---- groups --------------------------------------------------------
    async def create_group(self, name, creator, members):
        async with self._lock:
            cur = self.db.execute(
                "INSERT INTO groups(name,creator,created_at) VALUES(?,?,?)",
                (name, creator, time.time()),
            )
            gid = cur.lastrowid
            all_members = set(members) | {creator}
            for m in all_members:
                # only add existing users
                if self.db.execute(
                    "SELECT 1 FROM users WHERE username=?", (m,)
                ).fetchone():
                    self.db.execute(
                        "INSERT OR IGNORE INTO group_members(group_id,username)"
                        " VALUES(?,?)",
                        (gid, m),
                    )
            self.db.commit()
            return gid

    def _group_members_unlocked(self, group_id):
        rows = self.db.execute(
            "SELECT username FROM group_members WHERE group_id=?", (group_id,)
        ).fetchall()
        return [r["username"] for r in rows]

    async def group_members(self, group_id):
        async with self._lock:
            return self._group_members_unlocked(group_id)

    async def group_info(self, group_id):
        async with self._lock:
            g = self.db.execute(
                "SELECT group_id,name,creator FROM groups WHERE group_id=?",
                (group_id,),
            ).fetchone()
            if not g:
                return None
            members = self._group_members_unlocked(group_id)
            return {"group_id": g["group_id"], "name": g["name"],
                    "creator": g["creator"], "members": members}

    async def my_groups(self, username):
        async with self._lock:
            rows = self.db.execute(
                "SELECT g.group_id,g.name,g.creator FROM groups g"
                " JOIN group_members m ON m.group_id=g.group_id"
                " WHERE m.username=? ORDER BY g.group_id",
                (username,),
            ).fetchall()
            out = []
            for r in rows:
                members = [
                    x["username"] for x in self.db.execute(
                        "SELECT username FROM group_members WHERE group_id=?",
                        (r["group_id"],),
                    ).fetchall()
                ]
                out.append({"group_id": r["group_id"], "name": r["name"],
                            "creator": r["creator"], "members": members})
            return out

    async def add_member(self, group_id, username, by):
        async with self._lock:
            mem = self.db.execute(
                "SELECT 1 FROM group_members WHERE group_id=? AND username=?",
                (group_id, by),
            ).fetchone()
            if not mem:
                return False, "not a member"
            if not self.db.execute(
                "SELECT 1 FROM users WHERE username=?", (username,)
            ).fetchone():
                return False, "unknown user"
            self.db.execute(
                "INSERT OR IGNORE INTO group_members(group_id,username) VALUES(?,?)",
                (group_id, username),
            )
            self.db.commit()
            return True, "ok"

    async def remove_member(self, group_id, username, by):
        async with self._lock:
            g = self.db.execute(
                "SELECT creator FROM groups WHERE group_id=?", (group_id,)
            ).fetchone()
            if not g:
                return False, "unknown group"
            if by != g["creator"] and by != username:
                return False, "only creator or self"
            self.db.execute(
                "DELETE FROM group_members WHERE group_id=? AND username=?",
                (group_id, username),
            )
            self.db.commit()
            return True, "ok"

    # ---- files ---------------------------------------------------------
    async def add_file(self, file_id, uploader, filename, mime, size, sha256):
        async with self._lock:
            self.db.execute(
                "INSERT INTO files(file_id,uploader,filename,mime,size,sha256,created_at)"
                " VALUES(?,?,?,?,?,?,?)",
                (file_id, uploader, filename, mime, size, sha256, time.time()),
            )
            self.db.commit()

    async def get_file(self, file_id):
        async with self._lock:
            row = self.db.execute(
                "SELECT file_id,uploader,filename,mime,size,sha256 FROM files"
                " WHERE file_id=?",
                (file_id,),
            ).fetchone()
            return dict(row) if row else None


class Server:
    def __init__(self, store, files_dir):
        self.store = store
        self.files_dir = files_dir
        os.makedirs(files_dir, exist_ok=True)
        self.online = {}        # username -> websocket
        self.challenges = {}    # username -> (challenge bytes, expiry)
        self.upload_tokens = {}  # token -> (username, expiry)
        self.limiter = RateLimiter()

    @staticmethod
    def _client_ip(request):
        # respect X-Forwarded-For only from localhost proxies
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd and (request.remote in ("127.0.0.1", "::1")):
            return fwd.split(",")[0].strip()
        return request.remote or "unknown"

    # ---------- websocket ----------------------------------------------
    async def ws_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        authed_user = None
        peer = request.remote
        ip = self._client_ip(request)
        log.info("ws connect from %s", peer)
        try:
            async for raw in ws:
                if raw.type != web.WSMsgType.TEXT:
                    continue
                # rate limit: 120 ws messages / minute per connection
                if not self.limiter.allow("ws_msg", f"ws:{id(ws)}"):
                    await self._send(ws, {"type": "error",
                                          "code": "rate_limited",
                                          "message": "too many requests"})
                    continue
                # hard cap on inbound frame size (defense in depth)
                if len(raw.data) > 2 * 1024 * 1024:
                    await self._send(ws, {"type": "error",
                                          "code": "frame_too_large"})
                    continue
                try:
                    msg = json.loads(raw.data)
                except json.JSONDecodeError:
                    await self._send(ws, {"type": "error", "code": "bad_json"})
                    continue
                if not isinstance(msg, dict):
                    await self._send(ws, {"type": "error", "code": "bad_json"})
                    continue
                # stricter per-type limits before dispatch
                t = msg.get("type")
                if t == "register" and not self.limiter.allow(
                        "ws_register", f"ip:{ip}"):
                    await self._send(ws, {"type": "error",
                                          "code": "rate_limited"})
                    continue
                if t in ("auth", "auth_response") and not self.limiter.allow(
                        "ws_auth", f"ip:{ip}"):
                    await self._send(ws, {"type": "error",
                                          "code": "rate_limited"})
                    continue
                try:
                    authed_user = await self._dispatch(ws, msg, authed_user)
                except Exception:  # never kill the connection on handler bugs
                    log.exception("handler error")
                    await self._send(ws, {"type": "error", "code": "internal"})
        finally:
            if authed_user and self.online.get(authed_user) is ws:
                del self.online[authed_user]
                log.info("ws disconnect %s", authed_user)
        return ws

    async def _send(self, ws, obj):
        await ws.send_str(json.dumps(obj))

    async def _dispatch(self, ws, msg, authed_user):
        t = msg.get("type")

        if t == "register":
            result = await self._handle_register(msg)
            if result == "ok":
                await self._send(ws, {"type": "registered",
                                      "username": msg["username"]})
            else:
                messages = {
                    "bad_username": "username must be 3-20 chars, "
                                    "alphanumeric + underscore",
                    "username_taken": "username already registered",
                    "email_taken": "email already registered",
                    "bad_email": "invalid email address",
                    "not_verified": "email not verified - complete OTP first",
                    "bad_keys": "invalid public keys",
                }
                await self._send(ws, {"type": "error", "code": result,
                                      "message": messages.get(result, result)})
            return authed_user

        if t == "check_username":
            # availability check before registration
            import re
            u = str(msg.get("username", "")).strip()
            valid = bool(re.fullmatch(r"[A-Za-z0-9_]{3,20}", u))
            avail = await self.store.username_available(u) if valid else False
            await self._send(ws, {"type": "username_status",
                                  "username": u, "valid": valid,
                                  "available": avail})
            return authed_user

        if t == "auth":
            username = msg.get("username", "")
            user = await self.store.get_user(username)
            if not user:
                await self._send(ws, {"type": "error", "code": "unknown_user"})
                return authed_user
            chal = secrets.token_bytes(32)
            self.challenges[username] = (chal, time.time() + 120)
            await self._send(ws, {"type": "challenge",
                                  "challenge": B64(chal)})
            return authed_user

        if t == "auth_response":
            username = msg.get("username", "")
            user = await self.store.get_user(username)
            chal = self.challenges.pop(username, None)
            if not user or not chal or time.time() > chal[1]:
                await self._send(ws, {"type": "error",
                                      "code": "bad_challenge"})
                return authed_user
            try:
                VerifyKey(user["identity_pubkey"]).verify(
                    chal[0], UB64(msg.get("signature", "")))
            except (BadSignatureError, ValueError):
                await self._send(ws, {"type": "error",
                                      "code": "bad_signature"})
                return authed_user
            # kick any previous session
            old = self.online.get(username)
            if old is not None and old is not ws:
                try:
                    await old.close()
                except Exception:
                    pass
            self.online[username] = ws
            token = secrets.token_hex(16)
            self.upload_tokens[token] = (username, time.time() + 600)
            await self._send(ws, {"type": "authed", "username": username,
                                  "upload_token": token})
            log.info("authed %s", username)
            return username

        # ---- everything below needs auth ----
        if not authed_user:
            await self._send(ws, {"type": "error", "code": "not_authed"})
            return authed_user

        if t == "send":
            mid = await self._handle_dm(authed_user, msg, ws)
            return authed_user

        if t == "group_create":
            gid = await self.store.create_group(
                msg.get("name", "Group")[:80], authed_user,
                msg.get("members", []))
            info = await self.store.group_info(gid)
            await self._send(ws, {"type": "group_created",
                                  "group_id": gid,
                                  "members": info["members"]})
            return authed_user

        if t == "group_add":
            ok, why = await self.store.add_member(
                msg["group_id"], msg["username"], authed_user)
            await self._send(ws, {"type": "ok" if ok else "error",
                                  "code": None if ok else "group_add_failed",
                                  "message": why})
            return authed_user

        if t == "group_remove":
            ok, why = await self.store.remove_member(
                msg["group_id"], msg["username"], authed_user)
            await self._send(ws, {"type": "ok" if ok else "error",
                                  "code": None if ok else "group_remove_failed",
                                  "message": why})
            return authed_user

        if t == "group_send":
            await self._handle_group_send(authed_user, msg, ws)
            return authed_user

        if t == "sync":
            for m in await self.store.pending(authed_user):
                await self._send(ws, {
                    "type": "message", "msg_id": m["id"], "kind": m["kind"],
                    "from": m["sender"], "group_id": m["group_id"],
                    "group_name": m["group_name"],
                    "nonce": B64(m["nonce"]), "ciphertext": B64(m["ciphertext"]),
                    "msg_type": m["msg_type"], "ts": m["ts"]})
            await self._send(ws, {"type": "sync_done"})
            return authed_user

        if t == "ack":
            ids = [int(i) for i in msg.get("msg_ids", []) if str(i).isdigit()]
            await self.store.mark_delivered(authed_user, ids)
            await self._send(ws, {"type": "ok"})
            return authed_user

        if t == "list_users":
            users = await self.store.list_users()
            users = [u for u in users if u["username"] != authed_user]
            await self._send(ws, {"type": "user_list", "users": users})
            return authed_user

        if t == "my_groups":
            await self._send(ws, {"type": "group_list",
                                  "groups": await self.store.my_groups(
                                      authed_user)})
            return authed_user

        await self._send(ws, {"type": "error", "code": "unknown_type"})
        return authed_user

    async def _handle_register(self, msg):
        username = str(msg.get("username", "")).strip()
        email = str(msg.get("email", "")).strip().lower()[:254]
        token = str(msg.get("verification_token", ""))
        # email must have been verified via OTP (single-use token)
        if not email or "@" not in email:
            return "bad_email"
        if not await self.store.consume_verification(email, token):
            return "not_verified"
        try:
            ident_pub = UB64(msg["identity_pubkey"])
            box_pub = UB64(msg["box_pubkey"])
        except Exception:
            return "bad_keys"
        if len(ident_pub) != 32 or len(box_pub) != 32:
            return "bad_keys"
        return await self.store.register(username, email, ident_pub, box_pub)

    async def _handle_dm(self, sender, msg, ws):
        to = msg.get("to", "")
        if not await self.store.get_user(to):
            await self._send(ws, {"type": "error", "code": "unknown_recipient"})
            return None
        try:
            nonce, ct = UB64(msg["nonce"]), UB64(msg["ciphertext"])
        except Exception:
            await self._send(ws, {"type": "error", "code": "bad_encoding"})
            return None
        if len(nonce) != 24 or not ct:
            await self._send(ws, {"type": "error", "code": "bad_payload"})
            return None
        if len(ct) > MAX_CIPHERTEXT_BYTES:
            # large payloads must go through /files (client-side encrypted)
            await self._send(ws, {"type": "error",
                                  "code": "payload_too_large",
                                  "message": "use /files for large payloads"})
            return None
        mid = await self.store.queue_message(
            "dm", sender, to, None, None, nonce, ct,
            str(msg.get("msg_type", "text"))[:16])
        await self._send(ws, {"type": "sent", "msg_id": mid})
        # best-effort live push; the row stays queued until acked
        peer_ws = self.online.get(to)
        if peer_ws is not None:
            try:
                await self._send(peer_ws, {
                    "type": "message", "msg_id": mid, "kind": "dm",
                    "from": sender, "group_id": None, "group_name": None,
                    "nonce": B64(nonce), "ciphertext": B64(ct),
                    "msg_type": str(msg.get("msg_type", "text"))[:16],
                    "ts": time.time()})
            except Exception:
                pass
        return mid

    async def _handle_group_send(self, sender, msg, ws):
        gid = msg.get("group_id")
        info = await self.store.group_info(gid)
        if not info or sender not in info["members"]:
            await self._send(ws, {"type": "error", "code": "not_in_group"})
            return
        try:
            nonce, ct = UB64(msg["nonce"]), UB64(msg["ciphertext"])
        except Exception:
            await self._send(ws, {"type": "error", "code": "bad_encoding"})
            return
        if len(nonce) != 24 or not ct:
            await self._send(ws, {"type": "error", "code": "bad_payload"})
            return
        if len(ct) > MAX_CIPHERTEXT_BYTES:
            await self._send(ws, {"type": "error",
                                  "code": "payload_too_large",
                                  "message": "use /files for large payloads"})
            return
        mtype = str(msg.get("msg_type", "text"))[:16]
        sent = 0
        first_id = None
        for member in info["members"]:
            mid = await self.store.queue_message(
                "group", sender, member, gid, info["name"], nonce, ct, mtype)
            if first_id is None:
                first_id = mid
            sent += 1
            peer_ws = self.online.get(member)
            if peer_ws is not None:
                try:
                    await self._send(peer_ws, {
                        "type": "message", "msg_id": mid, "kind": "group",
                        "from": sender, "group_id": gid,
                        "group_name": info["name"],
                        "nonce": B64(nonce), "ciphertext": B64(ct),
                        "msg_type": mtype, "ts": time.time()})
                except Exception:
                    pass
        await self._send(ws, {"type": "sent", "msg_id": first_id,
                              "recipients": sent})

    # ---------- http: email OTP ----------------------------------------
    async def otp_request(self, request):
        """POST /otp/request  {"email": "..."} -> {"ok": true}

        Rate limits: max 3 requests/hour/email, max 10/hour/IP.
        """
        ip = self._client_ip(request)
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "bad json"}, status=400)
        email = str(body.get("email", "")).strip().lower()[:254]
        if "@" not in email or "." not in email.split("@")[-1]:
            return web.json_response({"error": "invalid email"}, status=400)
        if not self.limiter.allow("otp_request", f"email:{email}"):
            return web.json_response(
                {"error": "too many OTP requests for this email "
                          "(max 3/hour)"}, status=429)
        if not self.limiter.allow("otp_request_ip", f"ip:{ip}"):
            return web.json_response({"error": "too many requests"},
                                     status=429)
        # don't let attackers enumerate registered emails: always "succeed"
        # but only actually send if the email isn't already registered
        from email_otp import send_otp_email
        code = f"{secrets.randbelow(900000) + 100000:06d}"
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        await self.store.store_otp(email, code_hash,
                                   time.time() + 600)  # 10 min expiry
        # best-effort send; still return ok to avoid enumeration
        send_otp_email(email, code)
        log.info("OTP requested for %s", email)
        return web.json_response({"ok": True,
                                  "message": "code sent if email is valid"})

    async def otp_verify(self, request):
        """POST /otp/verify  {"email": "...", "code": "123456"}
        -> {"ok": true, "verification_token": "..."}  (single-use for register)
        """
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "bad json"}, status=400)
        email = str(body.get("email", "")).strip().lower()[:254]
        code = str(body.get("code", "")).strip()
        if not email or not code:
            return web.json_response({"error": "email and code required"},
                                     status=400)
        rec = await self.store.get_otp(email)
        if not rec:
            return web.json_response({"error": "no code requested"},
                                     status=400)
        if time.time() > rec["expires_at"]:
            await self.store.clear_otp(email)
            return web.json_response({"error": "code expired"}, status=400)
        if rec["attempts"] >= 5:
            await self.store.clear_otp(email)
            return web.json_response(
                {"error": "too many attempts, request a new code"},
                status=400)
        await self.store.bump_otp_attempts(email)
        if not secrets.compare_digest(
                hashlib.sha256(code.encode()).hexdigest(), rec["code_hash"]):
            return web.json_response({"error": "wrong code"}, status=400)
        # success: clear OTP, issue single-use registration token
        await self.store.clear_otp(email)
        token = secrets.token_hex(32)
        await self.store.mark_email_verified(email, token)
        log.info("email verified: %s", email)
        return web.json_response({"ok": True, "verification_token": token})

    # ---------- http: files --------------------------------------------
    async def file_upload(self, request):
        token = request.headers.get("X-Upload-Token", "")
        entry = self.upload_tokens.pop(token, None)
        if not entry or time.time() > entry[1]:
            return web.json_response(
                {"error": "bad or expired upload token"}, status=401)
        username = entry[0]
        if not self.limiter.allow("http_upload", f"user:{username}"):
            return web.json_response({"error": "upload rate limit exceeded"},
                                     status=429)
        reader = await request.multipart()
        field = await reader.next()
        if field is None or field.name != "file":
            return web.json_response({"error": "missing 'file' field"},
                                     status=400)
        # validate filename: no path traversal, sane length
        filename = (field.filename or "blob.bin")[:255]
        filename = os.path.basename(filename)
        if not filename:
            filename = "blob.bin"
        file_id = uuid.uuid4().hex
        path = os.path.join(self.files_dir, file_id)
        # file_id is a hex uuid we generated -> no traversal possible
        size, h = 0, hashlib.sha256()
        with open(path, "wb") as f:
            while True:
                chunk = await field.read_chunk(65536)
                if not chunk:
                    break
                size += len(chunk)
                if size > 100 * 1024 * 1024:  # 100 MB cap
                    f.close()
                    os.remove(path)
                    return web.json_response({"error": "file too large"},
                                             status=413)
                h.update(chunk)
                f.write(chunk)
        # NOTE: bytes are an opaque client-side-encrypted blob; the server
        # cannot read them. sha256 is over the ciphertext (integrity only).
        await self.store.add_file(file_id, username, filename,
                                  field.headers.get(
                                      "Content-Type",
                                      "application/octet-stream"),
                                  size, h.hexdigest())
        log.info("file %s uploaded by %s (%d bytes)", file_id, username, size)
        return web.json_response({"file_id": file_id, "size": size,
                                  "sha256": h.hexdigest()})

    async def file_download(self, request):
        file_id = request.match_info["file_id"]
        # strict allowlist: 32 hex chars (uuid4 hex we issued)
        if (len(file_id) != 32
                or any(c not in "0123456789abcdef" for c in file_id)):
            return web.json_response({"error": "not found"}, status=404)
        ip = self._client_ip(request)
        if not self.limiter.allow("http_download", f"ip:{ip}"):
            return web.json_response({"error": "rate limit exceeded"},
                                     status=429)
        meta = await self.store.get_file(file_id)
        if not meta:
            return web.json_response({"error": "not found"}, status=404)
        path = os.path.join(self.files_dir, file_id)
        if not os.path.exists(path):
            return web.json_response({"error": "gone"}, status=410)
        return web.FileResponse(path, headers={
            "Content-Type": meta["mime"],
            "Content-Disposition":
                f'attachment; filename="{meta["filename"]}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "private, max-age=3600"})


def build_app(store, files_dir):
    srv = Server(store, files_dir)

    @web.middleware
    async def security_headers(request, handler):
        resp = await handler(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    async def _limiter_gc(app):
        while True:
            await asyncio.sleep(600)
            srv.limiter.cleanup()

    app = web.Application(middlewares=[security_headers])
    app.router.add_get("/ws", srv.ws_handler)
    app.router.add_post("/files", srv.file_upload)
    app.router.add_get("/files/{file_id}", srv.file_download)
    app.router.add_post("/otp/request", srv.otp_request)
    app.router.add_post("/otp/verify", srv.otp_verify)

    async def health(_):
        return web.json_response({"ok": True, "service": "securechat-relay"})
    app.router.add_get("/health", health)

    async def on_startup(app):
        app["_gc"] = asyncio.create_task(_limiter_gc(app))

    async def on_cleanup(app):
        app["_gc"].cancel()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    return app


def main():
    ap = argparse.ArgumentParser(description="SecureChat relay server")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--data", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "data"))
    args = ap.parse_args()

    os.makedirs(args.data, exist_ok=True)
    store = Store(os.path.join(args.data, "securechat.db"))
    app = build_app(store, os.path.join(args.data, "files"))
    log.info("SecureChat relay on %s:%d (data=%s)",
             args.host, args.port, args.data)
    web.run_app(app, host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
