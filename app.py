# STAR LIKE API SRC UID PASSWORD
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE

from flask import Flask, request, jsonify
import asyncio
import aiohttp
import requests
import urllib3
import time
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

MAIN_KEY = b'Yg&tc%DEuh6%Zc^8'
MAIN_IV  = b'6oyZDr22E3ychjM%'

# ─────────────────────────────────────────────
#  Pure-Python Protobuf helpers
# ─────────────────────────────────────────────

def vr(n):
    d = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        d.append(b)
        if not n: break
    return bytes(d)

def pb(F):
    p = bytearray()
    for f, v in F.items():
        if isinstance(v, bool):
            p.extend(vr((f << 3) | 0)); p.extend(vr(1 if v else 0))
        elif isinstance(v, int):
            p.extend(vr((f << 3) | 0)); p.extend(vr(v))
        elif isinstance(v, str):
            d = v.encode(); p.extend(vr((f << 3) | 2)); p.extend(vr(len(d))); p.extend(d)
        elif isinstance(v, (bytes, bytearray)):
            d = bytes(v); p.extend(vr((f << 3) | 2)); p.extend(vr(len(d))); p.extend(d)
    return bytes(p)

def rv(data, pos):
    r = 0; s = 0
    while pos < len(data):
        b = data[pos]; pos += 1; r |= (b & 0x7F) << s
        if not (b & 0x80): break
        s += 7
    return r, pos

def parse(data):
    f = {}; pos = 0; n = len(data)
    while pos < n:
        try: k, pos = rv(data, pos)
        except: break
        fn = k >> 3; wt = k & 7
        try:
            if wt == 0:
                v, pos = rv(data, pos)
            elif wt == 2:
                ln, pos = rv(data, pos); v = data[pos:pos+ln]; pos += ln
            elif wt == 5:
                v = data[pos:pos+4]; pos += 4
            elif wt == 1:
                v = data[pos:pos+8]; pos += 8
            else: break
        except: break
        f.setdefault(fn, []).append(v)
    return f

# ─────────────────────────────────────────────
#  AES helpers
# ─────────────────────────────────────────────

def enc(p):
    pl = 16 - (len(p) % 16)
    return AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).encrypt(p + bytes([pl] * pl))

def dec(c):
    d = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV).decrypt(c)
    pl = d[-1]
    if 1 <= pl <= 16: d = d[:-pl]
    return d

def strip_prefix(b):
    if len(b) <= 64: return b
    try:
        if 8 in parse(b): return b
    except: pass
    try:
        if 8 in parse(b[64:]): return b[64:]
    except: pass
    return b[64:]

# ─────────────────────────────────────────────
#  Protobuf field helpers  (from info.py)
# ─────────────────────────────────────────────

def getv(f, n):
    v = f.get(n)
    if v is None: return None
    if isinstance(v, list): v = v[0]
    return v

def g(d, k):
    if not isinstance(d, dict): return None
    v = d.get(k)
    if isinstance(v, list): v = v[0] if v else None
    if isinstance(v, bytes):
        try: return v.decode()
        except: return v.hex()
    return v

def sub(fields, k):
    v = fields.get(k)
    if not v: return {}
    v = v[0]
    if isinstance(v, bytes): return parse(v)
    return v if isinstance(v, dict) else {}

def smart_decode(raw_bytes):
    try:
        f = parse(raw_bytes)
        if 1 in f and isinstance(f[1], list) and f[1]:
            return f, "raw_protobuf"
    except: pass
    for skip in (0, 16, 32, 64):
        try:
            body = raw_bytes[skip:]
            if len(body) % 16 != 0: continue
            f = parse(dec(body))
            if 1 in f: return f, f"aes_skip_{skip}"
        except: pass
    for skip in (16, 32, 64):
        try:
            f = parse(raw_bytes[skip:])
            if 1 in f: return f, f"raw_skip_{skip}"
        except: pass
    return None, "failed"

# ─────────────────────────────────────────────
#  Account loading
# ─────────────────────────────────────────────

def load_accounts(server_name: str) -> list:
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
    with open(filename, "r") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith('#') or ':' not in line:
                continue
            uid, password = line.split(':', 1)
            uid = uid.strip(); password = password.strip()
            if uid and password:
                accounts.append({"uid": uid, "password": password})

    print(f"✅ {len(accounts)} accounts loaded for {server_name}")
    return accounts

# ─────────────────────────────────────────────
#  Garena OAuth + MajorLogin  (info.py method)
# ─────────────────────────────────────────────

def oauth(uid, pwd):
    H = {"User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
         "Content-Type": "application/json; charset=utf-8"}
    try:
        R = requests.post(
            "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant",
            headers=H,
            json={"client_id": 100067,
                  "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                  "client_type": 2, "device_id": "", "password": pwd,
                  "response_type": "token", "uid": int(uid)},
            verify=False, timeout=20)
    except Exception as e:
        print(f"oauth err: {e}"); return None
    if R.status_code not in (200, 201): return None
    J = R.json()
    if J.get("code") != 0: return None
    d = J.get("data", {})
    return {"access_token": d.get("access_token"), "open_id": d.get("open_id")}

def build_login_payload(at, oi):
    P = {}
    P[3] = time.strftime("%Y-%m-%d %H:%M:%S"); P[4] = "free fire"; P[5] = 1; P[7] = "1.132.9"
    P[8] = "Android OS 14 / API-34 (UP1A.231005.007/V816.0.15.0.UNQMIXM)"
    P[9] = "Handheld"; P[10] = "Grameenphone"; P[11] = "CarrierDataNetwork"
    P[12] = 1666; P[13] = 750; P[14] = "352"; P[15] = "ARM64 FP ASIMD AES | 2400 | 8"
    P[16] = 5563; P[17] = "Mali-G57 MC2"
    P[18] = "OpenGL ES 3.2 v1.r32p1-01eac0.0a0b917d9265b4c01be9925306306139"
    P[19] = "Google|9cc73f7a-91f6-40f6-87ec-5b67e597eb8c"; P[20] = "59.152.5.188"
    P[21] = "en"; P[22] = oi; P[23] = "8"; P[24] = "Handheld"
    P[25] = "Xiaomi 2312DRAABI"; P[26] = "BD"; P[29] = at; P[30] = 1
    P[41] = "Grameenphone"; P[42] = "Cellular"
    P[57] = "7428b253defc164018c604a1ebbfebdf"
    P[60] = 109685; P[61] = 58294; P[62] = 797; P[63] = 18000; P[64] = 58818
    P[65] = 109685; P[66] = 58818; P[67] = 109685; P[73] = 2
    P[74] = "/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/lib/arm64"
    P[76] = 1
    P[77] = "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/~~cqQgpdMykLQEM3odipXatw==/com.dts.freefireth-G6e5yOt1dtuXG5Ambhj18g==/base.apk"
    P[78] = 3; P[79] = 2; P[81] = "64"; P[83] = "2019121229"; P[85] = 3; P[86] = "OpenGLES2"
    P[87] = 4095; P[88] = 8
    P[89] = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    P[90] = "Dhaka"; P[91] = "C"; P[92] = 8043; P[93] = "android"
    P[94] = "KqsHT4XbSZhqerDNUhjbS3DxG/4+I62zQU2tZFJN91kBUICAlZ5yujshLKvjlk/KiShfKfis8EeB1PMhFHIodWPncZC4fCHYF3TcTwNj95aWY/S3"
    P[95] = 111207; P[96] = '{"cur_rate":[60,90,120],"support_etc2":false}'
    P[97] = 1; P[98] = 1; P[99] = "4"; P[100] = "4"; P[102] = "GQ]        e"; P[103] = 1
    P[104] = 45174; P[105] = 1
    P[106] = "https://dl-bs.ggpolarbear.com/live/ABHotUpdates/|https://core-bs.ggpolarbear.com/live/ABHotUpdates/|a4332cb1c1a84e51dd77441e4856ed5a"
    P[107] = "1.9393e7b8e53e8aeb"
    return enc(pb(P))

def major_login(payload):
    H = {"User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
         "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
         "X-GA-SV": str(int(time.time())), "Authorization": "Bearer ",
         "X-GA": "v1 1", "ReleaseVersion": "OB55",
         "Content-Type": "application/x-www-form-urlencoded",
         "X-Unity-Version": "2018.4.12f1"}
    try:
        R = requests.post("https://loginbp.ppmainecoonghj.com/MajorLogin",
                          headers=H, data=payload, verify=False, timeout=20)
    except Exception as e:
        print(f"majorlogin err: {e}"); return None
    if R.status_code not in (200, 201) or not R.content: return None
    return R.content

def get_jwt(uid: str, pwd: str):
    """Returns (jwt, server_url) or None"""
    acc = oauth(uid, pwd)
    if not acc: return None
    ml = major_login(build_login_payload(acc["access_token"], acc["open_id"]))
    if not ml: return None
    body = strip_prefix(ml)
    f = parse(body)
    jwt_b = getv(f, 8); url_b = getv(f, 10)
    jwt = jwt_b.decode() if isinstance(jwt_b, bytes) else jwt_b
    url = url_b.decode() if isinstance(url_b, bytes) else url_b
    if not jwt: return None
    if not url or not url.startswith("http"):
        url = "https://clientbp.ppmainecoonghj.com"
    return jwt, url

# ─────────────────────────────────────────────
#  Player info  (info.py field mapping)
#  field 1  (outer) → BasicInfo submessage
#    field 3  → AccountName  (Nickname)
#    field 21 → AccountLikes
#  UID passed separately
# ─────────────────────────────────────────────

def get_player_info(uid: str, server_name: str, jwt: str, server_url: str = None) -> dict | None:
    if server_url:
        base = server_url.rstrip("/")
    elif server_name == "IND":
        base = "https://client.ind.freefiremobile.com"
    elif server_name in {"BR", "US", "SAC", "NA"}:
        base = "https://client.us.freefiremobile.com"
    else:
        base = "https://clientbp.ppmainecoonghj.com"

    payload = enc(pb({1: int(uid), 2: 7}))
    H = {"User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
         "Accept": "*/*", "Accept-Encoding": "deflate, gzip",
         "X-GA-SV": str(int(time.time())),
         "Authorization": f"Bearer {jwt}",
         "X-GA": "v1 1", "ReleaseVersion": "OB55",
         "Content-Type": "application/x-www-form-urlencoded",
         "X-Unity-Version": "2018.4.12f1"}
    try:
        R = requests.post(base + "/GetPlayerPersonalShow",
                          data=payload, headers=H, timeout=20, verify=False)
        if R.status_code != 200: return None
        raw, method = smart_decode(R.content)
        if not raw: return None

        bi = sub(raw, 1)   # BasicInfo — same as info.py

        likes    = g(bi, 21)   # AccountLikes  → field 21
        nickname = g(bi, 3)    # AccountName   → field 3

        return {
            "UID":            int(uid),
            "PlayerNickname": str(nickname) if nickname else "",
            "Likes":          int(likes) if likes else 0,
        }
    except Exception as e:
        print(f"❌ get_player_info error: {e}")
        return None

# ─────────────────────────────────────────────
#  Async JWT + like sender
# ─────────────────────────────────────────────

async def async_get_jwt(uid: str, pwd: str):
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, get_jwt, uid, pwd)

async def send_like_async(jwt: str, uid: str, server_url: str) -> bool:
    host = server_url.replace("https://", "").replace("http://", "").split("/")[0]
    headers = {
        "Expect": "100-continue",
        "Authorization": f"Bearer {jwt}",
        "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1", "ReleaseVersion": "OB55",
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
        "Host": host, "Connection": "Keep-Alive", "Accept-Encoding": "gzip",
    }
    # LikeProfile payload: field 1 = target uid (int), field 2 = region "ME"
    payload = enc(pb({1: int(uid), 2: "ME"}))
    url = server_url.rstrip("/") + "/LikeProfile"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                return resp.status == 200
    except: return False

async def process_account(target_uid: str, account: dict, semaphore: asyncio.Semaphore) -> tuple:
    async with semaphore:
        result = await async_get_jwt(account["uid"], account["password"])
        if not result: return False, account["uid"]
        jwt, server_url = result
        ok = await send_like_async(jwt, target_uid, server_url)
        if ok: liked_cache[target_uid].add(account["uid"])
        return ok, account["uid"]

async def send_all_likes(target_uid: str, server_name: str) -> dict:
    accounts = load_accounts(server_name)
    if not accounts:
        return {"success": 0, "failed": 0, "total": 0, "already_liked": 0, "fresh_used": 0}

    already_liked = liked_cache.get(target_uid, set())
    fresh = [a for a in accounts if a["uid"] not in already_liked]
    print(f"📊 Total:{len(accounts)}  Fresh:{len(fresh)}  Already:{len(already_liked)}")

    if not fresh:
        return {"success": 0, "failed": 0, "total": len(accounts),
                "already_liked": len(already_liked), "fresh_used": 0}

    random.shuffle(fresh)
    batch = fresh[:2000]
    semaphore = asyncio.Semaphore(25)
    tasks = [process_account(target_uid, acc, semaphore) for acc in batch]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    success = sum(1 for r in results if isinstance(r, tuple) and r[0])
    failed  = sum(1 for r in results if isinstance(r, tuple) and not r[0])
    return {"success": success, "failed": failed, "total": len(accounts),
            "already_liked": len(already_liked), "fresh_used": len(batch)}

# ─────────────────────────────────────────────
#  Misc
# ─────────────────────────────────────────────

def get_today_midnight():
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

    # Daily limit
    today_midnight = get_today_midnight()
    count, last_reset = tracker[client_ip]
    if last_reset < today_midnight:
        tracker[client_ip] = [0, time.time()]; count = 0
    if count >= KEY_LIMIT:
        return jsonify({"error": "Daily limit reached", "remains": f"(0/{KEY_LIMIT})"}), 429

    # Get JWT for info checks
    accounts = load_accounts(server_name) or load_accounts("IND")
    if not accounts:
        return jsonify({"error": f"No accounts found for server {server_name}"}), 500

    check_jwt = None; check_server = None
    for acc in accounts[:5]:
        result = get_jwt(acc["uid"], acc["password"])
        if result:
            check_jwt, check_server = result
            print(f"✅ Token OK: {acc['uid']} → {check_server}")
            break

    if not check_jwt:
        return jsonify({"error": "Token generation failed"}), 500

    # Before likes
    before_info = get_player_info(uid, server_name, check_jwt, check_server)
    if not before_info:
        return jsonify({"error": "Invalid UID or server", "status": 0}), 200

    before_like = before_info["Likes"]

    # Send likes
    asyncio.run(send_all_likes(uid, server_name))

    # After likes
    after_info = get_player_info(uid, server_name, check_jwt, check_server)
    if not after_info:
        return jsonify({"error": "Could not verify likes after command", "status": 0}), 200

    after_like  = after_info["Likes"]
    like_given  = after_like - before_like
    status_code = 1 if like_given != 0 else 2

    if like_given > 0:
        tracker[client_ip][0] += 1; count += 1

    remains = KEY_LIMIT - count
    return jsonify({
        "LikesGivenByAPI":    like_given,
        "LikesafterCommand":  after_like,
        "LikesbeforeCommand": before_like,
        "PlayerNickname":     after_info["PlayerNickname"],
        "UID":                after_info["UID"],
        "status":             status_code,
        "remains":            f"({remains}/{KEY_LIMIT})",
    })


@app.route('/reset-cache', methods=['GET'])
def reset_cache():
    if request.args.get("key") != "SIAM":
        return jsonify({"error": "Invalid key"}), 403
    liked_cache.clear()
    return jsonify({"message": "Cache cleared", "credit": "@STAR_GMR"})


if __name__ == '__main__':
    print("🚀 Smart Like System started!")
    print("   account_ind.txt  → IND")
    print("   account_br.txt   → BR/US/SAC/NA")
    print("   account_bd.txt   → BD/RU")
    app.run(host='0.0.0.0', port=5001, debug=True, use_reloader=False)

# STAR LIKE API SRC UID PASSWORD
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
