# STAR LIKE API SRC UID PASSWORD
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE

from flask import Flask, request, jsonify
import asyncio
import aiohttp
import requests
import urllib3
import time
import json
import os
import random
from collections import defaultdict
from datetime import datetime
from Crypto.Cipher import AES

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

KEY_LIMIT = 90
tracker = defaultdict(lambda: [0, time.time()])
liked_cache = defaultdict(set)

# ─────────────────────────────────────────────
#  Protobuf helpers (pure-Python, no .proto files needed)
# ─────────────────────────────────────────────

def vr(n):
    """Encode integer as varint bytes."""
    d = []
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            b |= 0x80
        d.append(b)
        if not n:
            break
    return bytes(d)

def pb(F):
    """Encode a dict {field_number: value} into protobuf wire format."""
    p = bytearray()
    for f, v in F.items():
        if isinstance(v, bool):
            p.extend(vr((f << 3) | 0))
            p.extend(vr(1 if v else 0))
        elif isinstance(v, int):
            p.extend(vr((f << 3) | 0))
            p.extend(vr(v))
        elif isinstance(v, str):
            d = v.encode()
            p.extend(vr((f << 3) | 2))
            p.extend(vr(len(d)))
            p.extend(d)
        elif isinstance(v, (bytes, bytearray)):
            d = bytes(v)
            p.extend(vr((f << 3) | 2))
            p.extend(vr(len(d)))
            p.extend(d)
    return bytes(p)

def rv(data, pos):
    """Decode varint from data at pos, return (value, new_pos)."""
    r = 0
    s = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, pos

def parse_pb(data):
    """Parse raw protobuf bytes into {field_number: [values]}."""
    f = {}
    pos = 0
    n = len(data)
    while pos < n:
        try:
            k, pos = rv(data, pos)
        except Exception:
            break
        fn = k >> 3
        wt = k & 7
        try:
            if wt == 0:
                v, pos = rv(data, pos)
            elif wt == 2:
                ln, pos = rv(data, pos)
                v = data[pos:pos + ln]
                pos += ln
            elif wt == 5:
                v = data[pos:pos + 4]
                pos += 4
            elif wt == 1:
                v = data[pos:pos + 8]
                pos += 8
            else:
                break
        except Exception:
            break
        f.setdefault(fn, []).append(v)
    return f

def strip_prefix(b):
    """Strip the 64-byte Garena login-response prefix if present."""
    if len(b) <= 64:
        return b
    try:
        if 8 in parse_pb(b):
            return b
    except Exception:
        pass
    try:
        if 8 in parse_pb(b[64:]):
            return b[64:]
    except Exception:
        pass
    return b[64:]

# ─────────────────────────────────────────────
#  AES-CBC encryption
# ─────────────────────────────────────────────

_AES_KEY = b'Yg&tc%DEuh6%Zc^8'
_AES_IV  = b'6oyZDr22E3ychjM%'

def aes_encrypt(plaintext: bytes) -> bytes:
    """AES-128-CBC encrypt with PKCS#7 padding."""
    pl = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pl] * pl)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(padded)

def enc_uid(uid: str) -> bytes:
    """Encrypt UID protobuf for use in API calls (returns raw bytes)."""
    payload = pb({1: int(uid), 2: "ME"})
    return aes_encrypt(payload)

def enc_like(uid: str, region: str) -> bytes:
    """Encrypt like-request protobuf (field 1 = uid, field 2 = region)."""
    payload = pb({1: int(uid), 2: region})
    return aes_encrypt(payload)

# ─────────────────────────────────────────────
#  Account loading
# ─────────────────────────────────────────────

def load_accounts(server_name: str) -> list:
    """Load UID:Password pairs from the appropriate account file."""
    if server_name == "IND":
        filename = "account_ind.txt"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        filename = "account_br.txt"
    else:
        filename = "account_bd.txt"

    if not os.path.exists(filename):
        print(f"⚠️  {filename} not found, trying account_ind.txt")
        filename = "account_ind.txt"
        if not os.path.exists(filename):
            print("❌ No account file found")
            return []

    accounts = []
    print(f"📂 Loading from: {filename} for server {server_name}")
    with open(filename, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if ':' in line:
                uid, password = line.split(':', 1)
                uid = uid.strip()
                password = password.strip()
                if uid and password:
                    accounts.append({"uid": uid, "password": password})

    print(f"✅ {len(accounts)} accounts loaded for {server_name}")
    return accounts

# ─────────────────────────────────────────────
#  Garena OAuth + JWT (new.py method)
# ─────────────────────────────────────────────

def oauth_guest_token(uid: str, pwd: str) -> dict | None:
    """Obtain Garena OAuth guest token."""
    headers = {
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
        "Content-Type": "application/json; charset=utf-8",
    }
    body = {
        "client_id": 100067,
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_type": 2,
        "device_id": "",
        "password": pwd,
        "response_type": "token",
        "uid": int(uid),
    }
    try:
        r = requests.post(
            "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
            headers=headers, json=body, verify=False, timeout=20,
        )
    except Exception:
        return None
    if r.status_code not in (200, 201):
        return None
    try:
        j = r.json()
    except Exception:
        return None
    if j.get("code") != 0:
        return None
    d = j.get("data", {})
    if not d.get("access_token") or not d.get("open_id"):
        return None
    return d

def get_jwt(uid: str, pwd: str):
    """
    Full login flow:
      1. Garena OAuth → access_token + open_id
      2. MajorLogin (protobuf) → JWT + server URL

    Returns (jwt_string, server_url) or None on failure.
    """
    acc = oauth_guest_token(uid, pwd)
    if not acc:
        return None

    P = {}
    P[3]  = time.strftime("%Y-%m-%d %H:%M:%S")
    P[4]  = "free fire"
    P[5]  = 1
    P[7]  = "1.132.9"
    P[8]  = "Android OS 14 / API-34 (UP1A.231005.007/V816.0.15.0.UNQMIXM)"
    P[9]  = "Handheld"
    P[10] = "Grameenphone"
    P[11] = "CarrierDataNetwork"
    P[12] = 1666
    P[13] = 750
    P[14] = "352"
    P[15] = "ARM64 FP ASIMD AES | 2400 | 8"
    P[16] = 5563
    P[17] = "Mali-G57 MC2"
    P[18] = "OpenGL ES 3.2 v1.r32p1-01eac0.0a0b917d9265b4c01be9925306306139"
    P[19] = "Google|9cc73f7a-91f6-40f6-87ec-5b67e597eb8c"
    P[20] = "59.152.5.188"
    P[21] = "en"
    P[22] = acc["open_id"]
    P[23] = "8"
    P[24] = "Handheld"
    P[25] = "Xiaomi 2312DRAABI"
    P[26] = "BD"
    P[29] = acc["access_token"]
    P[30] = 1
    P[41] = "Grameenphone"
    P[42] = "Cellular"
    P[57] = "7428b253defc164018c604a1ebbfebdf"
    P[60] = 109685; P[61] = 58294; P[62] = 797; P[63] = 18000
    P[64] = 58818;  P[65] = 109685; P[66] = 58818; P[67] = 109685
    P[73] = 2
    P[74] = "/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/lib/arm64"
    P[76] = 1
    P[77] = "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/base.apk"
    P[78] = 3; P[79] = 2; P[81] = "64"; P[83] = "2019121229"; P[85] = 3
    P[86] = "OpenGLES2"; P[87] = 4095; P[88] = 8
    P[89] = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    P[90] = "Dhaka"; P[91] = "C"; P[92] = 8043; P[93] = "android"
    P[94] = "KqsHT4XbSZhqerDNUhjbS3DxG/4+I62zQU2tZFJN91kBUICAlZ5yujshLKvjlk/KiShfKfis8EeB1PMhFHIodWPncZC4fCHYF3TcTwNj95aWY/S3"
    P[95] = 111207
    P[96] = '{"cur_rate":[60,90,120],"support_etc2":false}'
    P[97] = 1; P[98] = 1; P[99] = "4"; P[100] = "4"
    P[102] = "GQ]        e"; P[103] = 1; P[104] = 45174; P[105] = 1
    P[106] = "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a"
    P[107] = "1.9393e7b8e53e8aeb"

    login_headers = {
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Accept": "*/*",
        "Accept-Encoding": "deflate, gzip",
        "X-GA-SV": str(int(time.time())),
        "Authorization": "Bearer ",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Unity-Version": "2018.4.12f1",
    }

    try:
        r = requests.post(
            "https://loginbp.ppmainecoonghj.com/MajorLogin",
            headers=login_headers,
            data=aes_encrypt(pb(P)),
            verify=False,
            timeout=20,
        )
    except Exception:
        return None

    if r.status_code not in (200, 201) or not r.content:
        return None

    parsed = parse_pb(strip_prefix(r.content))
    jwt_bytes   = parsed.get(8, [None])[0]
    server_bytes = parsed.get(10, [None])[0]

    if not isinstance(jwt_bytes, bytes):
        return None

    server = server_bytes.decode() if isinstance(server_bytes, bytes) else "https://clientbp.ppmainecoonghj.com"
    if not server.startswith("http"):
        server = "https://" + server

    return jwt_bytes.decode(), server

# ─────────────────────────────────────────────
#  Async JWT (wraps sync get_jwt for use with asyncio)
# ─────────────────────────────────────────────

async def async_get_jwt(uid: str, pwd: str):
    """Run get_jwt in executor so it doesn't block the event loop."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_jwt, uid, pwd)

# ─────────────────────────────────────────────
#  Player info  (protobuf, pure-Python)
# ─────────────────────────────────────────────

def get_player_info_raw(uid: str, server_name: str, jwt: str, server_url: str = None) -> dict | None:
    """
    Fetch GetPlayerPersonalShow and return parsed protobuf dict.
    Falls back to per-server URLs when server_url is not provided.
    """
    if server_url:
        url = server_url.rstrip("/") + "/GetPlayerPersonalShow"
    elif server_name == "IND":
        url = "https://client.ind.freefiremobile.com/GetPlayerPersonalShow"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        url = "https://client.us.freefiremobile.com/GetPlayerPersonalShow"
    else:
        url = "https://clientbp.ppmainecoonghj.com/GetPlayerPersonalShow"

    edata = enc_uid(uid)
    headers = {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Authorization": f"Bearer {jwt}",
        "Content-Type": "application/x-www-form-urlencoded",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
    }
    try:
        r = requests.post(url, data=edata, headers=headers, verify=False, timeout=10)
        return parse_pb(r.content)
    except Exception:
        return None

def extract_account_info(parsed: dict) -> dict | None:
    """
    Pull UID, nickname, and like count from a parsed GetPlayerPersonalShow response.
    Field layout (best-effort reverse-engineered):
      outer field 1 → AccountInfo message
        field 1  → UID (int)
        field 4  → Nickname (string)
        field 82 → Likes (int)   ← adjust if your server uses a different field
    """
    try:
        account_msg = parsed.get(1, [None])[0]
        if not isinstance(account_msg, bytes):
            return None
        inner = parse_pb(account_msg)

        def _int(field):
            vals = inner.get(field, [])
            return int(vals[0]) if vals else 0

        def _str(field):
            vals = inner.get(field, [])
            v = vals[0]
            return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)

        return {
            "UID":            _int(1),
            "PlayerNickname": _str(4),
            "Likes":          _int(82),   # adjust field number if needed
        }
    except Exception:
        return None

# ─────────────────────────────────────────────
#  Async like sender
# ─────────────────────────────────────────────

async def send_like_async(jwt: str, uid: str, server_url: str) -> bool:
    """Send a single LikeProfile request."""
    host = server_url.replace("https://", "").replace("http://", "").split("/")[0]
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": host,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
    }
    payload = enc_like(uid, "ME")
    url = server_url.rstrip("/") + "/LikeProfile"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                return resp.status == 200
    except Exception:
        return False

async def process_account(target_uid: str, account: dict, semaphore: asyncio.Semaphore) -> tuple:
    """Login + send like for one account. Returns (success: bool, account_uid: str)."""
    async with semaphore:
        result = await async_get_jwt(account["uid"], account["password"])
        if not result:
            return False, account["uid"]
        jwt, server_url = result
        ok = await send_like_async(jwt, target_uid, server_url)
        if ok:
            liked_cache[target_uid].add(account["uid"])
        return ok, account["uid"]

async def send_all_likes(target_uid: str, server_name: str) -> dict:
    """Dispatch likes from all fresh accounts concurrently."""
    accounts = load_accounts(server_name)
    if not accounts:
        return {"success": 0, "failed": 0, "total": 0, "already_liked": 0, "fresh_used": 0}

    already_liked = liked_cache.get(target_uid, set())
    fresh = [a for a in accounts if a["uid"] not in already_liked]

    print(f"📊 Total: {len(accounts)}  Fresh: {len(fresh)}  Already liked: {len(already_liked)}")

    if not fresh:
        return {"success": 0, "failed": 0, "total": len(accounts), "already_liked": len(already_liked), "fresh_used": 0}

    random.shuffle(fresh)
    batch = fresh[:2000]
    semaphore = asyncio.Semaphore(25)
    tasks = [process_account(target_uid, acc, semaphore) for acc in batch]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    success = sum(1 for r in results if isinstance(r, tuple) and r[0])
    failed  = sum(1 for r in results if isinstance(r, tuple) and not r[0])

    return {
        "success": success,
        "failed": failed,
        "total": len(accounts),
        "already_liked": len(already_liked),
        "fresh_used": len(batch),
    }

# ─────────────────────────────────────────────
#  Misc helpers
# ─────────────────────────────────────────────

def get_today_midnight_timestamp():
    now = datetime.now()
    return datetime(now.year, now.month, now.day).timestamp()

# ─────────────────────────────────────────────
#  Flask routes
# ─────────────────────────────────────────────

@app.route('/like', methods=['GET'])
def handle_requests():
    uid         = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    key         = request.args.get("key")
    client_ip   = request.remote_addr

    if key != "SIAM":
        return jsonify({"error": "Invalid or missing API key 🔑"}), 403

    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    valid_servers = ["IND", "BR", "US", "SAC", "NA", "BD", "RU"]
    if server_name not in valid_servers:
        return jsonify({"error": f"Invalid server. Use: {valid_servers}"}), 400

    # Daily limit check
    today_midnight = get_today_midnight_timestamp()
    count, last_reset = tracker[client_ip]
    if last_reset < today_midnight:
        tracker[client_ip] = [0, time.time()]
        count = 0
    if count >= KEY_LIMIT:
        return jsonify({"error": "Daily limit reached", "remains": f"(0/{KEY_LIMIT})"}), 429

    # Obtain a JWT for the before/after info checks
    accounts = load_accounts(server_name)
    if not accounts:
        accounts = load_accounts("IND")
    if not accounts:
        return jsonify({"error": f"No accounts found for server {server_name}"}), 500

    check_jwt = None
    check_server = None
    for acc in accounts[:5]:
        result = get_jwt(acc["uid"], acc["password"])
        if result:
            check_jwt, check_server = result
            print(f"✅ Token generated with UID: {acc['uid']}")
            break

    if not check_jwt:
        return jsonify({"error": "Token generation failed – no valid accounts"}), 500

    # Before-like info
    before_parsed = get_player_info_raw(uid, server_name, check_jwt, check_server)
    if before_parsed is None:
        return jsonify({"error": "Invalid UID or server", "status": 0}), 200

    before_info = extract_account_info(before_parsed)
    if not before_info:
        return jsonify({"error": "Data parsing failed (before)", "status": 0}), 200
    before_like = before_info["Likes"]

    # Send likes
    result = asyncio.run(send_all_likes(uid, server_name))

    # After-like info
    after_parsed = get_player_info_raw(uid, server_name, check_jwt, check_server)
    if after_parsed is None:
        return jsonify({"error": "Could not verify likes after command", "status": 0}), 200

    after_info = extract_account_info(after_parsed)
    if not after_info:
        return jsonify({"error": "Data parsing failed (after)", "status": 0}), 200

    after_like  = after_info["Likes"]
    like_given  = after_like - before_like
    status_code = 1 if like_given != 0 else 2

    if like_given > 0:
        tracker[client_ip][0] += 1
        count += 1

    remains = KEY_LIMIT - count

    return jsonify({
        "LikesGivenByAPI":   like_given,
        "LikesafterCommand": after_like,
        "LikesbeforeCommand": before_like,
        "PlayerNickname":    after_info["PlayerNickname"],
        "UID":               after_info["UID"],
        "status":            status_code,
        "remains":           f"({remains}/{KEY_LIMIT})",
    })


@app.route('/reset-cache', methods=['GET'])
def reset_cache():
    """Clear the liked-accounts cache."""
    if request.args.get("key") != "SIAM":
        return jsonify({"error": "Invalid key"}), 403
    liked_cache.clear()
    return jsonify({"message": "Cache cleared", "credit": "@STAR_GMR"})


if __name__ == '__main__':
    print("🚀 Server started – Smart Like System!")
    print("📁 Account files:")
    print("   - account_ind.txt  (IND server)")
    print("   - account_br.txt   (BR/US/SAC/NA servers)")
    print("   - account_bd.txt   (BD/RU server)")
    print("🧠 Smart feature: tracks which accounts already liked")
    print("⚡ Only fresh accounts will send likes")
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)

# STAR LIKE API SRC UID PASSWORD
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
