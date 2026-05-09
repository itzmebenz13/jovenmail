import os
import uuid
import time
import threading
import queue
import requests
import urllib3
import json
from datetime import datetime, date
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, request, Response, jsonify, render_template
from flask_cors import CORS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# ─── ADMIN KEY ────────────────────────────────────────────────────────────────
ADMIN_KEY = "BossJobean2026"

# ─── VOUCHER ACCESS CODES ─────────────────────────────────────────────────────
# Maps voucher_batch_id -> list of valid access codes for that voucher
VOUCHER_ACCESS_CODES = {
    "ph0313":   ["ph0313n4"],
    "ph0313 4vc": ["ph0313n3", "ph0313n4", "ph0313n5", "ph0313n6"],
    "ph031381": ["ph031381n1", "ph031381n2", "ph031381n3"],
    "gm0pha":   ["gm0pha_a1", "gm0pha_a2", "gm0pha_a3"],
}

# ─── COIN COST PER VOUCHER ────────────────────────────────────────────────────
# All batches cost 1 Gold coin per use.
VOUCHER_COIN_COST = {
    "ph0313":     {"coin": "gold", "label": "ph0313 (79%)"},
    "ph0313 4vc": {"coin": "gold", "label": "ph0313 4vc"},
    "ph031381":   {"coin": "gold", "label": "ph0313 (81%)"},
    "gm0pha":     {"coin": "gold", "label": "gm0pha"},
}

# ─── ALLOWED CODES PER BATCH (server-side enforcement) ────────────────────────
# Non-admin users may ONLY submit codes from this list for their active batch.
# ph0313 (default) accepts all 8 codes — merges ph0313 (4) + ph0313 4vc (4).
# pkgId is enforced server-side to prevent tampering.
VALID_BATCH_CODES = {
    #           ── ph0313 default: 8 codes ──
    "ph0313":     ["ph0313n1", "ph0313n2", "ph0313n3", "ph0313n4",
                   "ph0313n5", "ph0313n6", "ph0313n9", "ph0313n10"],
    #           ── ph0313 4vc: its own 4 codes ──
    "ph0313 4vc": ["ph0313n3",  "ph0313n4",  "ph0313n5",  "ph0313n6"],
    #           ── ph031381 (81%): 4 codes ──
    "ph031381":   ["ph0313n5", "ph0313n10", "ph0313n15", "ph0313n19"],
    #           ── gm0pha: 4 codes ──
    "gm0pha":     ["gm0pha11", "gm0pha12",  "gm0pha13",  "gm0pha14"],
}

# ─── PACKAGE IDs PER BATCH ────────────────────────────────────────────────────
BATCH_PKG_IDS = {
    "ph0313":     "17139475",
    "ph0313 4vc": "17139475",
    "ph031381":   "17139475",
    "gm0pha":     "17131185",
}

# ─── USER DATABASE (file-backed JSON) ─────────────────────────────────────────
USERS_FILE       = os.environ.get("USERS_FILE",      "users.json")
DAILY_COIN_FILE  = os.environ.get("DAILY_COIN_FILE", "daily_coins.json")
CLAIM_LOG_FILE   = os.environ.get("CLAIM_LOG_FILE",  "claim_log.json")
_users_lock      = threading.Lock()
_daily_lock      = threading.Lock()
_log_lock        = threading.Lock()


def _load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)


def get_user(access_key):
    with _users_lock:
        return _load_users().get(access_key)


def save_user(access_key, user_data):
    with _users_lock:
        users = _load_users()
        users[access_key] = user_data
        _save_users(users)


def all_users():
    with _users_lock:
        return _load_users()


def _load_daily_config():
    if os.path.exists(DAILY_COIN_FILE):
        try:
            with open(DAILY_COIN_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return {"bronze": 0, "silver": 0, "gold": 1}


def _save_daily_config(cfg):
    with open(DAILY_COIN_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def _apply_daily_coins():
    today_str = date.today().isoformat()
    cfg = _load_daily_config()
    with _users_lock:
        users = _load_users()
        changed = False
        for key, user in users.items():
            if user.get("last_daily", "") != today_str:
                user.setdefault("coins", {"bronze": 0, "silver": 0, "gold": 0})
                for ct in ("bronze", "silver", "gold"):
                    amt = cfg.get(ct, 0)
                    if amt > 0:
                        user["coins"][ct] = user["coins"].get(ct, 0) + amt
                user["last_daily"] = today_str
                changed = True
        if changed:
            _save_users(users)


def _daily_coin_scheduler():
    while True:
        try:
            _apply_daily_coins()
        except Exception as e:
            print(f"[daily-coins] Error: {e}")
        time.sleep(3600)


threading.Thread(target=_daily_coin_scheduler, daemon=True).start()


# ─── CLAIM LOG ───────────────────────────────────────────────────────────────
def _load_logs():
    if os.path.exists(CLAIM_LOG_FILE):
        try:
            with open(CLAIM_LOG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def _save_logs(logs):
    with open(CLAIM_LOG_FILE, "w") as f:
        json.dump(logs, f, indent=2)


def _append_log(entry):
    """Thread-safe log append. Keeps newest 200 entries."""
    with _log_lock:
        logs = _load_logs()
        logs.insert(0, entry)
        if len(logs) > 200:
            logs = logs[:200]
        _save_logs(logs)


def _update_log(log_id, result, detail=""):
    """Update an existing log entry by log_id."""
    with _log_lock:
        logs = _load_logs()
        for entry in logs:
            if entry.get("log_id") == log_id:
                entry["result"] = result
                entry["detail"] = detail
                entry["completed_at"] = datetime.now().isoformat()
                break
        _save_logs(logs)


# ─── GEMINI API KEY (file-backed; admin sets via /admin/set_gemini_key) ──────
GEMINI_KEY_FILE = os.environ.get("GEMINI_KEY_FILE", "gemini_key.json")
_gemini_lock = threading.Lock()


def _load_gemini_key_unlocked():
    if os.path.exists(GEMINI_KEY_FILE):
        try:
            with open(GEMINI_KEY_FILE, "r") as f:
                return (json.load(f) or {}).get("key", "")
        except Exception:
            pass
    return ""


def _save_gemini_key_unlocked(key):
    with open(GEMINI_KEY_FILE, "w") as f:
        json.dump({"key": key or ""}, f)


def get_gemini_key():
    with _gemini_lock:
        return _load_gemini_key_unlocked()


def set_gemini_key(key):
    with _gemini_lock:
        _save_gemini_key_unlocked(key)


# ─── SHEIN API CONSTANTS ──────────────────────────────────────────────────────
COUPON_URL   = "https://api-service.shein.com/promotion/coupon/bind_coupon"
DELIVERY_URL = "https://api-shein.shein.com/deliveryapi/delivery-material/material_list"
LANGUAGE     = "en"

ERR_INVALID_PKG     = 1000
ERR_ALREADY_CLAIMED = 501405
ERR_LOGIN_CODES     = {"401", "100002", "200401", "10000", "460101"}
ERR_LOGIN_KEYWORDS  = ("please login", "login", "not logged", "unauthorized",
                       "user not exist", "\u672a\u767b\u5f55")


def build_headers(cfg, token):
    claim_country  = cfg.get("claim_country", "PH")
    currency_map   = {"PH": "PHP", "MY": "MYR", "TH": "THB"}
    claim_currency = currency_map.get(claim_country, "PHP")
    return {
        "app-from": "shein", "siteuid": "android",
        "appcountry": cfg.get("appcountry", "GB"), "devtype": "Android",
        "clientid": "100", "ugid": cfg.get("ugid", ""),
        "accept": "application/json", "device": cfg.get("device_info", ""),
        "armortoken": cfg.get("armor_token", ""), "applanguage": LANGUAGE,
        "usercountry": claim_country, "version": cfg.get("app_version", "11.2.3"),
        "devicelanguage": LANGUAGE, "dev-id": cfg.get("device_id", ""),
        "sortuid": cfg.get("sortuid", ""), "device_language": LANGUAGE,
        "apptype": "shein", "localcountry": claim_country,
        "smdeviceid": cfg.get("smdevice_id", ""), "deviceid": cfg.get("device_id", ""),
        "platform": "app-native", "appname": "shein app",
        "appversion": cfg.get("app_version", "11.2.3"), "newuid": cfg.get("sortuid", ""),
        "language": LANGUAGE, "currency": claim_currency, "network-type": "WIFI",
        "token": token, "os-version": "14", "devicesystemversion": "Android14",
        "appcurrency": claim_currency,
        "user-agent": f"Shein {cfg.get('app_version','11.2.3')} Android 14 {cfg.get('device_info','')} {cfg.get('appcountry','GB')} {LANGUAGE} {cfg.get('sortuid','')}",
        "x-gw-auth": cfg.get("gw_auth", ""), "content-type": "application/json; charset=utf-8",
    }


def build_delivery_headers(cfg, token):
    claim_country  = cfg.get("claim_country", "PH")
    currency_map   = {"PH": "PHP", "MY": "MYR", "TH": "THB"}
    claim_currency = currency_map.get(claim_country, "PHP")
    gm_device = cfg.get("gm_device_id", cfg.get("device_id", ""))
    gm_site   = cfg.get("gm_site", "andshph")
    av        = cfg.get("app_version", "11.2.3")
    di        = cfg.get("device_info", "")
    return {
        "host": "api-shein.shein.com", "content-type": "application/json",
        "accept": "application/json, text/plain, */*", "appname": "shein app",
        "apptype": "shein", "brand": "shein", "channel": "h5",
        "siteuid": gm_site, "localcountry": claim_country,
        "currency": claim_currency, "appcurrency": claim_currency,
        "applanguage": LANGUAGE, "language": LANGUAGE, "timezone": "GMT+8",
        "appversion": av, "deviceid": gm_device,
        "smdeviceid": cfg.get("smdevice_id", ""), "ugid": cfg.get("ugid", ""),
        "armortoken": cfg.get("armor_token", ""), "x-gw-auth": cfg.get("gw_auth", ""),
        "token": token, "x-request-by": "bridgeX", "route-bff": "TRUE",
        "user-agent": f"Mozilla/5.0 (Linux; Android 14; {di} Build/UKQ1; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/118.0.0.0 Mobile Safari/537.36 SheinApp(shein/{av}) TTID/shein Wing/1.0.1",
        "referer": f"https://api-shein.shein.com/ark/11504?app=shein&device_type=android&language=en&site_uid={gm_site}&region=PH",
        "origin": "https://api-shein.shein.com", "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors", "sec-fetch-dest": "empty",
        "accept-encoding": "gzip, deflate, br", "accept-language": "en-PH,en-US;q=0.9,en;q=0.8",
    }


def is_login_error(top_code, top_msg):
    if top_code in ERR_LOGIN_CODES:
        return True
    return any(kw in top_msg.lower() for kw in ERR_LOGIN_KEYWORDS)


def sse(msg):
    return f"data: {msg}\n\n"


def run_collect(cfg, q):
    tokens = cfg.get("tokens", [])
    codes  = cfg.get("codes", [])
    pkg_id = cfg.get("pkg_id", "")
    mode   = cfg.get("mode", "bind")

    def emit(msg): q.put(msg)

    if mode == "brute":
        _run_brute(cfg, q)
        return

    emit("=" * 60)
    emit("  SHEIN COUPON COLLECTOR  —  App API Mode")
    emit("=" * 60)
    emit(f"  Accounts : {len(tokens)}")
    emit(f"  Codes    : {len(codes)}")
    emit(f"  Package  : {pkg_id}")
    emit(f"  Country  : {cfg.get('claim_country','PH')}")
    emit("=" * 60)

    delay = int(cfg.get("account_delay", 3))
    for i, token in enumerate(tokens):
        emit(f"\n{'#'*60}")
        emit(f"  Account {i+1}/{len(tokens)}  [...{token[-20:]}]")
        emit(f"{'#'*60}")
        if mode == "delivery":
            _collect_delivery(cfg, token, emit)
        else:
            _collect_bind(cfg, token, codes, pkg_id, emit)
        if i < len(tokens) - 1:
            emit(f"\n  Waiting {delay}s before next account...")
            time.sleep(delay)

    emit("\n" + "=" * 60)
    emit("  All done!")
    emit("=" * 60)
    q.put(None)


def _collect_bind(cfg, token, codes, pkg_id, emit):
    headers = build_headers(cfg, token)
    payload = {
        "couponPackages": [{"couponPackageId": str(pkg_id), "couponCodes": ",".join(codes)}],
        "scene": "home", "idempotentCode": str(uuid.uuid4()),
    }
    emit(f"\n  {'─'*54}")
    emit(f"  Package  : {pkg_id}")
    emit(f"  Country  : {cfg.get('claim_country','PH')}")
    emit(f"  Claiming {len(codes)} code(s): {', '.join(codes)}")
    emit(f"  {'─'*54}")
    try:
        r = requests.post(COUPON_URL, json=payload, headers=headers, timeout=15, verify=False)
        try: raw = r.json()
        except: raw = {}
        data = raw if isinstance(raw, dict) else {}
        top_code = str(data.get("code") or data.get("ret_msg_code") or "")
        top_msg  = str(data.get("msg")  or data.get("tips") or "")
        info     = (data.get("info") or {}) if isinstance(data.get("info"), dict) else {}
        success_list = [str(c).strip() for c in (info.get("successCodeList") or []) if c]
        fail_list    = [str(c).strip() for c in (info.get("failCodeList") or []) if c]
        result_list  = info.get("bindResult") or []
        result_list  = result_list if isinstance(result_list, list) else []

        if is_login_error(top_code, top_msg):
            emit(f"  \U0001f512 NOT LOGGED IN \u2014 Please login. (code={top_code})")
            return
        if top_code == str(ERR_ALREADY_CLAIMED):
            for code in codes: emit(f"  \u26a0\ufe0f  {code} \u2014 ALREADY CLAIMED [501405]")
        elif success_list:
            emit(f"  \u2705 CLAIMED! codes={', '.join(success_list)}")
        elif result_list:
            claimed_c, conflict_c, other_c = [], [], []
            for item in result_list:
                if not isinstance(item, dict): continue
                cv = str(item.get("couponCode") or "?")
                ec = str(item.get("errorCode") or item.get("code") or "")
                if ec in ("0","200",""): claimed_c.append(cv)
                elif ec == str(ERR_ALREADY_CLAIMED): conflict_c.append(cv)
                else: other_c.append(f"{cv}[{ec}]")
            if claimed_c: emit(f"  \u2705 CLAIMED! {claimed_c}")
            for code in conflict_c: emit(f"  \u26a0\ufe0f  {code} \u2014 ALREADY CLAIMED [501405]")
            if other_c: emit(f"  \u274c FAILED \u2192 {other_c}")
        elif fail_list:
            emit(f"  \u274c FAILED {fail_list}")
        elif top_code not in ("0","200",""):
            emit(f"  \u274c ERR {top_code}: {top_msg[:80]}")
        elif top_code in ("0","200"):
            for code in codes: emit(f"  \u26a0\ufe0f  {code} \u2014 already owned or ambiguous (code={top_code})")
        else:
            emit(f"  \u2753 Ambiguous response \u2014 code={top_code} msg={top_msg[:60]}")
    except requests.exceptions.Timeout:
        emit("  \u274c Request timed out")
    except Exception as e:
        emit(f"  \u274c Error: {str(e)[:120]}")
    emit(f"  {'─'*54}")


def _collect_delivery(cfg, token, emit):
    gm_site = cfg.get("gm_site", "andshph")
    gm_mid  = cfg.get("gm_mid", "4142402")
    claim_country  = cfg.get("claim_country", "PH")
    claim_currency = {"PH":"PHP","MY":"MYR","TH":"THB"}.get(claim_country, "PHP")
    av        = cfg.get("app_version", "11.2.3")
    gm_device = cfg.get("gm_device_id", cfg.get("device_id", ""))

    headers = build_delivery_headers(cfg, token)
    payload = {
        "client_info": {"app_version": av, "client_id": 100, "currency": claim_currency,
                        "dev_id": gm_device, "language": LANGUAGE, "site_uid": gm_site,
                        "token": token, "brand": "shein"},
        "material_request_info": {
            "mid": gm_mid,
            "param_map": {"coupon_common_req": {"coupon_type": 2, "coupon_sequence": 3}, "auto_bind": True},
            "data_type": "SwiftCouponOnePlugin", "data_scene": 0,
            "data_scene_flag": "0_SwiftCouponOnePlugin"},
        "ext_map": {},
    }
    emit(f"\n  {'─'*54}")
    emit(f"  Mode     : DELIVERY API (auto_bind)")
    emit(f"  MID      : {gm_mid}")
    emit(f"  Country  : {claim_country} ({claim_currency})")
    emit(f"  {'─'*54}")
    try:
        r = requests.post(DELIVERY_URL, json=payload, headers=headers,
                          params={"sw_site": gm_site, "sw_lang": LANGUAGE}, timeout=15, verify=False)
        try: data = r.json()
        except: data = {}
        code = str(data.get("code", ""))
        if code not in ("0","200"):
            top_msg_d = str(data.get("msg","Unknown"))
            if is_login_error(code, top_msg_d):
                emit(f"  \U0001f512 NOT LOGGED IN \u2014 Please login. (code={code})")
            else:
                emit(f"  \u274c API error: {top_msg_d}")
            return
        info         = data.get("info") or {}
        coupon_info  = info.get("coupon_info") or {}
        bind_result  = coupon_info.get("bind_result") or {}
        bind_data    = bind_result.get("bindResult") or {}
        success_list = bind_data.get("successList") or []
        fail_list    = bind_data.get("failList") or []
        hit_coupon   = coupon_info.get("hit_coupon") or []
        recv_coupon  = coupon_info.get("received_coupon") or []
        if success_list:
            emit(f"  \u2705 {len(success_list)} claimed, {len(fail_list)} failed")
            for c in success_list:
                emit(f"     \u2713 {c.get('couponCode','?')} (id:{c.get('couponId','?')})")
        elif hit_coupon:
            emit(f"  \u26a0\ufe0f  Already claimed \u2014 {len(hit_coupon)} coupon(s) already in account")
        elif recv_coupon:
            emit(f"  \u2705 {len(recv_coupon)} already received")
        else:
            emit(f"  \u2753 No bind result \u2014 bindCode={bind_result.get('bindCode','')} detail={info.get('detail_msg') or data.get('msg') or 'No result'}")
    except requests.exceptions.Timeout:
        emit("  \u274c Request timed out")
    except Exception as e:
        emit(f"  \u274c Error: {str(e)[:120]}")
    emit(f"  {'─'*54}")


def _run_brute(cfg, q):
    tokens = cfg.get("tokens", [])
    codes  = cfg.get("codes", [])
    start  = int(cfg.get("brute_start", 17130000))
    end    = int(cfg.get("brute_end",   17140000))
    threads     = min(int(cfg.get("brute_threads", 10)), 30)
    max_claims  = int(cfg.get("brute_max_claims", 1))
    claim_country = cfg.get("claim_country", "PH")
    claim_currency = {"PH":"PHP","MY":"MYR","TH":"THB"}.get(claim_country, "PHP")
    token = tokens[0] if tokens else ""

    print_lock  = threading.Lock()
    claims_lock = threading.Lock()
    done_lock   = threading.Lock()
    stop_event  = threading.Event()
    claims_total  = [0]
    done_count    = [0]
    already_claimed = []

    def emit(msg):
        with print_lock: q.put(msg)

    pkg_range = list(range(start, end + 1))
    total = len(pkg_range)
    emit("=" * 64)
    emit("  BRUTE-FORCE MODE  —  live output")
    emit(f"  Range   : {start} \u2192 {end}  ({total} IDs)")
    emit(f"  Threads : {threads}")
    emit(f"  Stop at : {max_claims} claim(s)  (0 = unlimited)")
    emit(f"  Country : {claim_country} ({claim_currency})")
    emit(f"  Codes   : {', '.join(codes)}")
    emit("=" * 64)

    def probe(pkg_id):
        if stop_event.is_set(): return
        headers = build_headers(cfg, token)
        payload = {
            "couponPackages": [{"couponPackageId": str(pkg_id), "couponCodes": ",".join(codes)}],
            "scene": "home", "idempotentCode": str(uuid.uuid4()),
        }
        with done_lock:
            done_count[0] += 1
            done = done_count[0]
        pct = min(done * 100 // total, 100)
        try:
            r = requests.post(COUPON_URL, json=payload, headers=headers, timeout=12, verify=False)
            try: raw = r.json()
            except: raw = {}
            data = raw if isinstance(raw, dict) else {}
            top_code = str(data.get("code") or data.get("ret_msg_code") or "")
            top_msg  = str(data.get("msg")  or data.get("tips") or "")
            info = (data.get("info") or {}) if isinstance(data.get("info"), dict) else {}
            success_list = [str(c).strip() for c in (info.get("successCodeList") or []) if c]
            pkg_code   = str(info.get("couponPackageCode") or "")
            error_code = str(info.get("errorCode") or "")

            if top_code == str(ERR_INVALID_PKG): return
            if top_code == str(ERR_ALREADY_CLAIMED) or pkg_code == str(ERR_ALREADY_CLAIMED) or error_code == str(ERR_ALREADY_CLAIMED):
                emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u26a0  ALREADY CLAIMED [501405]")
                already_claimed.append(pkg_id); return
            if success_list:
                with claims_lock:
                    claims_total[0] += len(success_list)
                    total_so_far = claims_total[0]
                    if max_claims > 0 and claims_total[0] >= max_claims: stop_event.set()
                emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u2605 CLAIMED! codes=[{', '.join(success_list)}] total={total_so_far}"); return
            result_list = info.get("bindResult") or []
            result_list = result_list if isinstance(result_list, list) else []
            if result_list:
                claimed_c, conflict_c, other_c = [], [], []
                for item in result_list:
                    if not isinstance(item, dict): continue
                    cv = str(item.get("couponCode") or "?")
                    ec = str(item.get("errorCode") or item.get("code") or "")
                    if ec in ("0","200",""): claimed_c.append(cv)
                    elif ec == str(ERR_ALREADY_CLAIMED): conflict_c.append(cv)
                    else: other_c.append(f"{cv}[{ec}]")
                if claimed_c:
                    with claims_lock:
                        claims_total[0] += len(claimed_c)
                        total_so_far = claims_total[0]
                        if max_claims > 0 and claims_total[0] >= max_claims: stop_event.set()
                    emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u2605 CLAIMED! {claimed_c}")
                if conflict_c: emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u26a0  [501405] \u2192 {conflict_c}")
                if other_c:    emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u2717 FAIL \u2192 {other_c}")
                return
            fail_list = [str(c).strip() for c in (info.get("failCodeList") or []) if c]
            if fail_list:
                emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u2717 FAILED {fail_list}"); return
            if top_code not in ("0","200",""):
                emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u2717 ERR {top_code}: {top_msg[:50]}")
        except requests.exceptions.Timeout:
            emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u2717 TIMEOUT")
        except Exception as e:
            emit(f"  [{pct:3d}%] [{done}/{total}] pkg={pkg_id} \u2717 EXC: {str(e)[:80]}")

    with ThreadPoolExecutor(max_workers=threads) as exe:
        futs = [exe.submit(probe, pkg) for pkg in pkg_range]
        try:
            for fut in as_completed(futs):
                if stop_event.is_set():
                    exe.shutdown(wait=False, cancel_futures=True); break
        except Exception: pass

    emit("=" * 64)
    emit(f"  Done. Scanned {done_count[0]}/{total} IDs.")
    emit(f"  Total claimed   : {claims_total[0]} coupon(s)")
    emit(f"  Already claimed : {len(already_claimed)} package(s)")
    for p in already_claimed: emit(f"    \u2192 {p}")
    emit("=" * 64)
    q.put(None)


# ─── ROUTES ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return "", 404

@app.route("/mainscript.html")
def mainscript():
    return render_template("mainscript.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/user/login", methods=["POST"])
def user_login():
    data = request.get_json(force=True) or {}
    key  = data.get("access_key", "").strip()
    if not key:
        return jsonify({"error": "No access key provided"}), 400
    gemini_key = get_gemini_key()
    if key == ADMIN_KEY:
        return jsonify({"ok": True, "is_admin": True, "username": "Admin",
                        "coins": {"bronze": 999, "silver": 999, "gold": 999},
                        "gemini_key": gemini_key})
    user = get_user(key)
    if not user:
        return jsonify({"error": "Invalid access key"}), 401
    _apply_daily_coins()
    user = get_user(key)
    return jsonify({"ok": True, "is_admin": False,
                    "username": user.get("username", "User"),
                    "coins": user.get("coins", {"bronze": 0, "silver": 0, "gold": 0}),
                    "gemini_key": gemini_key})


@app.route("/user/use_coin", methods=["POST"])
def use_coin():
    data  = request.get_json(force=True) or {}
    key   = data.get("access_key", "").strip()
    batch = data.get("batch", "").strip()
    if not key or not batch:
        return jsonify({"error": "Missing access_key or batch"}), 400

    # Build a log entry regardless of admin/user
    log_id = str(uuid.uuid4())
    now_str = datetime.now().isoformat()

    if key == ADMIN_KEY:
        _append_log({
            "log_id":    log_id,
            "user":      "Admin",
            "access_key": "[admin]",
            "batch":     batch,
            "coin_type": "—",
            "result":    "pending",
            "detail":    "",
            "created_at": now_str,
            "completed_at": None,
        })
        return jsonify({"ok": True, "coins": {"bronze": 999, "silver": 999, "gold": 999},
                        "used_coin": "—", "log_id": log_id})

    cost_info = VOUCHER_COIN_COST.get(batch)
    if not cost_info:
        return jsonify({"error": f"Unknown batch: {batch}"}), 400
    coin_type = cost_info["coin"]
    with _users_lock:
        users = _load_users()
        user  = users.get(key)
        if not user:
            return jsonify({"error": "Invalid access key"}), 401
        coins   = user.setdefault("coins", {"bronze": 0, "silver": 0, "gold": 0})
        balance = coins.get(coin_type, 0)
        if balance <= 0:
            return jsonify({"error": f"Not enough {coin_type} coins for {cost_info['label']}"}), 402
        coins[coin_type] = balance - 1
        _save_users(users)

    _append_log({
        "log_id":     log_id,
        "user":       user.get("username", "User"),
        "access_key": key,
        "batch":      batch,
        "coin_type":  coin_type,
        "result":     "pending",
        "detail":     "",
        "created_at": now_str,
        "completed_at": None,
    })
    return jsonify({"ok": True, "coins": coins, "used_coin": coin_type, "log_id": log_id})


def _require_admin(data):
    return data.get("admin_key") == ADMIN_KEY


@app.route("/admin/users", methods=["POST"])
def admin_list_users():
    data = request.get_json(force=True) or {}
    if not _require_admin(data): return jsonify({"error": "Unauthorized"}), 401
    users = all_users()
    result = [{"key": k, "username": v.get("username",""),
               "coins": v.get("coins", {"bronze":0,"silver":0,"gold":0}),
               "last_daily": v.get("last_daily","")} for k, v in users.items()]
    return jsonify({"ok": True, "users": result})


@app.route("/admin/create_user", methods=["POST"])
def admin_create_user():
    data = request.get_json(force=True) or {}
    if not _require_admin(data): return jsonify({"error": "Unauthorized"}), 401
    key      = data.get("key", "").strip()
    username = data.get("username", "User").strip()
    coins    = data.get("coins", {"bronze": 0, "silver": 0, "gold": 0})
    if not key: return jsonify({"error": "No key provided"}), 400
    if get_user(key): return jsonify({"error": f"Key already exists"}), 409
    save_user(key, {"username": username,
                    "coins": {"bronze": int(coins.get("bronze",0)),
                              "silver": int(coins.get("silver",0)),
                              "gold":   int(coins.get("gold",0))},
                    "last_daily": "", "created": datetime.now().isoformat()})
    return jsonify({"ok": True, "key": key})


@app.route("/admin/set_coins", methods=["POST"])
def admin_set_coins():
    data = request.get_json(force=True) or {}
    if not _require_admin(data): return jsonify({"error": "Unauthorized"}), 401
    key   = data.get("key", "").strip()
    coins = data.get("coins", {})
    with _users_lock:
        users = _load_users()
        user  = users.get(key)
        if not user: return jsonify({"error": "User not found"}), 404
        user["coins"] = {"bronze": int(coins.get("bronze", user["coins"].get("bronze",0))),
                         "silver": int(coins.get("silver", user["coins"].get("silver",0))),
                         "gold":   int(coins.get("gold",   user["coins"].get("gold",0)))}
        _save_users(users)
    return jsonify({"ok": True, "coins": user["coins"]})


@app.route("/admin/add_coins", methods=["POST"])
def admin_add_coins():
    data = request.get_json(force=True) or {}
    if not _require_admin(data): return jsonify({"error": "Unauthorized"}), 401
    key   = data.get("key", "").strip()
    coins = data.get("coins", {})
    with _users_lock:
        users = _load_users()
        user  = users.get(key)
        if not user: return jsonify({"error": "User not found"}), 404
        for ct in ("bronze","silver","gold"):
            user["coins"][ct] = user["coins"].get(ct,0) + int(coins.get(ct,0))
        _save_users(users)
    return jsonify({"ok": True, "coins": user["coins"]})


@app.route("/admin/delete_user", methods=["POST"])
def admin_delete_user():
    data = request.get_json(force=True) or {}
    if not _require_admin(data): return jsonify({"error": "Unauthorized"}), 401
    key = data.get("key", "").strip()
    with _users_lock:
        users = _load_users()
        if key not in users: return jsonify({"error": "User not found"}), 404
        del users[key]
        _save_users(users)
    return jsonify({"ok": True})


@app.route("/admin/get_daily_config", methods=["POST"])
def admin_get_daily_config():
    data = request.get_json(force=True) or {}
    if not _require_admin(data): return jsonify({"error": "Unauthorized"}), 401
    return jsonify({"ok": True, "daily_coins": _load_daily_config()})


@app.route("/admin/set_daily_config", methods=["POST"])
def admin_set_daily_config():
    data = request.get_json(force=True) or {}
    if not _require_admin(data): return jsonify({"error": "Unauthorized"}), 401
    cfg = {"bronze": int(data.get("bronze",0)),
           "silver": int(data.get("silver",0)),
           "gold":   int(data.get("gold",1))}
    _save_daily_config(cfg)
    return jsonify({"ok": True, "daily_coins": cfg})


@app.route("/admin/set_gemini_key", methods=["POST"])
def admin_set_gemini_key():
    """Admin-only — store the shared Gemini API key in gemini_key.json.
    Pass {admin_key, gemini_key}. Empty gemini_key clears it."""
    data = request.get_json(force=True) or {}
    if not _require_admin(data):
        return jsonify({"error": "Unauthorized"}), 401
    new_key = (data.get("gemini_key") or "").strip()
    if new_key and not (new_key.startswith("AIza") or new_key.startswith("AQ.")):
        return jsonify({"error": "Invalid key format (expected AIza... or AQ....)"}), 400
    set_gemini_key(new_key)
    return jsonify({"ok": True})


@app.route("/logs", methods=["POST"])
def get_logs():
    data = request.get_json(force=True) or {}
    key  = data.get("access_key", "").strip()
    if not key:
        return jsonify({"error": "Missing access_key"}), 400
    is_admin = (key == ADMIN_KEY)
    logs = _load_logs()
    if not is_admin:
        # Non-admins only see their own logs (mask access_key)
        user = get_user(key)
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        logs = [l for l in logs if l.get("access_key") == key]
    # Remove raw access_key from response for safety
    safe = []
    for l in logs:
        e = dict(l)
        e.pop("access_key", None)
        safe.append(e)
    return jsonify({"ok": True, "logs": safe})


@app.route("/logs/update", methods=["POST"])
def update_log():
    data   = request.get_json(force=True) or {}
    key    = data.get("access_key", "").strip()
    log_id = data.get("log_id", "").strip()
    result = data.get("result", "unknown").strip()   # 'success' | 'failed' | 'already_claimed' | 'stopped'
    detail = data.get("detail", "").strip()
    if not key or not log_id:
        return jsonify({"error": "Missing access_key or log_id"}), 400
    is_admin = (key == ADMIN_KEY)
    if not is_admin and not get_user(key):
        return jsonify({"error": "Unauthorized"}), 401
    _update_log(log_id, result, detail)
    return jsonify({"ok": True})


@app.route("/logs/clear", methods=["POST"])
def clear_logs():
    data = request.get_json(force=True) or {}
    if not _require_admin(data):
        return jsonify({"error": "Unauthorized"}), 401
    with _log_lock:
        _save_logs([])
    return jsonify({"ok": True})


@app.route("/run", methods=["POST"])
def run_script():
    data = request.get_json(force=True) or {}
    access_key = data.get("access_key", "").strip()
    is_admin   = access_key == ADMIN_KEY
    if not is_admin:
        if not get_user(access_key):
            return jsonify({"error": "Unauthorized"}), 401
    cfg   = data.get("cfg", {})
    batch = data.get("batch", "").strip()
    if not cfg.get("tokens"):
        return jsonify({"error": "No tokens provided"}), 400

    # ── Server-side code whitelist enforcement for non-admins ──
    if not is_admin and batch:
        allowed = VALID_BATCH_CODES.get(batch)
        if allowed is None:
            return jsonify({"error": f"Unknown batch: {batch}"}), 400
        submitted = cfg.get("codes", [])
        bad = [c for c in submitted if c not in allowed]
        if bad:
            return jsonify({"error": f"Unauthorized codes for batch '{batch}': {', '.join(bad)}"}), 403

    q = queue.Queue()
    def worker():
        try: run_collect(cfg, q)
        except Exception as e:
            q.put(f"  \u274c Fatal error: {str(e)}"); q.put(None)
    threading.Thread(target=worker, daemon=True).start()

    def generate():
        while True:
            try:
                msg = q.get(timeout=120)
                if msg is None: yield sse("[DONE]"); break
                yield sse(msg)
            except queue.Empty:
                yield sse("  \u26a0\ufe0f  Timeout waiting for output")
                yield sse("[DONE]"); break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
