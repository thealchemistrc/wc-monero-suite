#!/usr/bin/env python3
"""
xmr-pushd - Device-side daemon for the Monero Push Companion plugin.

Polls a local monero-wallet-rpc instance on loopback, detects incoming
transfers, and pushes confirmations + pre-generated addresses to a
WordPress server running the companion plugin.

Requirements (any always-on host: Termux/Android, laptop, VPS, Raspberry Pi...):
  apt install python3 python3-pip curl
  pip install pynacl

Usage:
  python3 xmr-pushd.py [config.json] [--debug] [--log-file=PATH]
  python3 xmr-pushd.py --edit [config.json]     (interactive config editor)
  python3 xmr-pushd.py --prune-addresses [--prune-dry-run] [--prune-keep=N]
      One-shot cleanup: stop watching never-funded, non-active subaddresses
      and ask the server to drop them from its address pool. The wallet FILE
      keeps them - monero-wallet-rpc has no RPC to delete subaddresses.

Runs with:
  bash xmr-push-start.sh          (tmux + wake-lock, recommended)
  python3 xmr-pushd.py            (foreground, for LAN testing)
  python3 xmr-pushd.py --debug    (verbose output)
  python3 xmr-pushd.py --edit     (TUI to edit config - ideal on a device)

Failure modes to be aware of:
  - Device clock drift > 5 min from server → pushes silently rejected. The
    daemon self-heals: it measures the server clock offset from every
    authenticated status response (state "server_offset") and adjusts all
    outgoing payload timestamps via server_now(); large corrections log a
    WARN. NTP sync is still recommended.
  - Wallet-rpc restart → indices remain tracked, state resumes after restart.
  - State file corruption → auto-resets (atomic write via rename).
  - Network drop (mobile/WiFi/Mullvad) → retried next cycle, no crash.
  - WordPress shared secret changed → device pushes fail until config updated.

Security model (server compromised):
  The WordPress server holds the shared secret, so a compromised server can
  produce valid encrypted status responses. This daemon treats every byte from
  the server as untrusted: response size is capped, plaintext is capped, JSON
  is validated against a strict schema, all numeric fields are range-checked,
  active_indices is bounded and filtered, and wallet-RPC is locked to loopback.
  No server value is ever executed, evaled, or used as code/path without
  validation. DoS via oversized or malformed payloads is bounded.
"""

import os, sys, json, time, signal, subprocess, ssl, base64, traceback, re, stat, hmac, atexit
import urllib.request
import urllib.parse
import urllib.error

try:
    from nacl.secret import SecretBox
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import RawEncoder, HexEncoder
    from nacl.bindings import crypto_kx_keypair, crypto_scalarmult
    from nacl.hash import generichash
    from nacl.utils import random as nacl_random
    HAS_NACL = True
except ImportError:
    HAS_NACL = False

DEFAULTS = {
    "wp_url": "",
    "wp_post_field": "msg",
    "wp_status_param": "t",
    "shared_secret_hex": "",

    "wallet_rpc_url": "http://127.0.0.1:18089/json_rpc",
    "wallet_rpc_user": "",
    "wallet_rpc_pass": "",

    "wallet_id": "default",
    "account_index": 0,
    "network": "mainnet",

    "poll_interval": 30,
    "status_interval": 43200,
    "min_pool_free": 10,
    "batch_size": 50,
    "address_generation_cooldown": 3600,

    "state_file": "xmr-pushd-state.json",
    "debug": False,
    "tls_verify": True,
    "signing_privkey_hex": "",
    "signing_pubkey_hex": "",
    "servers": [],
}

RUNNING = True
DEBUG = False

LOG_FILE = None             # optional mirror of console output (--log-file=PATH)
_ORIG_CONSOLE_MODE = None   # saved conhost input mode, restored on exit
NO_CONSOLE_FIX = False      # --no-console-fix: leave conhost mode untouched

_DEVICE_LOG = []
_DEVICE_LOG_MAX = 200

MAX_HTTP_RESPONSE_BYTES = 65536
MAX_DECRYPTED_BYTES = 16384
MAX_ENCRYPTED_B64_CHARS = 22000
MAX_ACTIVE_INDICES = 500
CONF_CAP = 100
MAX_GENERATED_INDICES = 5000
MAX_POOL_VALUE = 1000000
MAX_BURN_RATE = 1000000
MAX_JSON_KEYS = 20
MAX_LOG_MSG_CHARS = 2000
CONSECUTIVE_INVALID_THRESHOLD = 5
PAIRING_TIMEOUT_SECONDS = 120

MONERO_NETWORK_PORT_BASE = {"mainnet": 18000, "testnet": 28000, "stagenet": 38000}

_consecutive_invalid = 0

def _monero_port_for_network(port, target_network):
    try:
        port = int(port)
    except Exception:
        return None
    if target_network not in MONERO_NETWORK_PORT_BASE:
        return None
    if not (18080 <= port <= 18089 or 28080 <= port <= 28089 or 38080 <= port <= 38089):
        return None
    suffix = port % 100
    return MONERO_NETWORK_PORT_BASE[target_network] + suffix

def _update_url_port(url, new_port):
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname or "127.0.0.1"
        if not host:
            return url
        if p.scheme not in ("http", "https"):
            return url
        userinfo = ""
        if p.username:
            userinfo = p.username
            if p.password:
                userinfo += f":{p.password}"
            userinfo += "@"
        if ":" in host and not host.startswith("[") and p.hostname and ":" in p.hostname:
            host_part = f"[{host}]"
        else:
            host_part = host
        netloc = f"{userinfo}{host_part}:{int(new_port)}"
        return urllib.parse.urlunparse((p.scheme, netloc, p.path or "/json_rpc", p.params, p.query, p.fragment))
    except Exception:
        return url

def _auto_correct_wallet_port(cfg, old_network=None):
    url = cfg.get("wallet_rpc_url", "")
    net = cfg.get("network", "mainnet")
    try:
        cur_port = urllib.parse.urlparse(url).port
    except Exception:
        return False
    if cur_port is None:
        return False
    expected = _monero_port_for_network(cur_port, net)
    if expected is None or expected == cur_port:
        return False
    new_url = _update_url_port(url, expected)
    if new_url == url:
        return False
    cfg["wallet_rpc_url"] = new_url
    if old_network:
        log(f"Network changed {old_network} → {net}: auto-adjusted wallet_rpc_url port {cur_port} → {expected}", "INFO")
    else:
        log(f"wallet_rpc_url port {cur_port} mismatched network {net} - auto-corrected to {expected}", "WARN")
    return True

def device_log_entries():
    return list(_DEVICE_LOG)

def device_log_clear():
    global _DEVICE_LOG
    _DEVICE_LOG = []

def _sanitize_log_str(s, limit=MAX_LOG_MSG_CHARS):
    if not isinstance(s, str):
        s = str(s)
    s = s.replace("\x1b", "").replace("\r", " ").replace("\n", " ")
    s = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)
    if len(s) > limit:
        s = s[:limit] + "...[truncated]"
    return s

def _capture_log(level, msg, data=None):
    entry = {"t": int(time.time()), "level": str(level)[:16], "msg": _sanitize_log_str(msg)}
    if data is not None:
        try:
            d = json.dumps(data, separators=(',', ':')) if isinstance(data, (dict, list)) else str(data)
            entry["d"] = _sanitize_log_str(d, 800)
        except Exception:
            entry["d"] = _sanitize_log_str(str(data), 800)
    _DEVICE_LOG.append(entry)
    while len(_DEVICE_LOG) > _DEVICE_LOG_MAX:
        _DEVICE_LOG.pop(0)

def log(msg, level="INFO"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    safe = _sanitize_log_str(str(msg))
    safe_level = _sanitize_log_str(str(level), 16)
    line = f"[{ts}] [{safe_level}] {safe}"
    print(line, flush=True)
    _capture_log(safe_level, safe)
    if LOG_FILE:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as _f:
                _f.write(line + "\n")
        except Exception:
            pass

def debug(msg):
    if DEBUG:
        log(msg, "DEBUG")

def die(msg, code=1):
    log(msg, "FATAL")
    sys.exit(code)

# ---------------------------------------------------------------------------
# Config loading & strict validation
# ---------------------------------------------------------------------------

_ALLOWED_CONFIG_KEYS = set(DEFAULTS.keys()) | {"servers", "signing_privkey_hex", "signing_pubkey_hex"}
_ALLOWED_SERVER_KEYS = {"wp_url", "wp_post_field", "wp_status_param", "shared_secret_hex", "label", "pinned_kx_pk"}
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

def _validate_wallet_rpc_url(url):
    if not isinstance(url, str) or not url:
        return False, "empty"
    try:
        p = urllib.parse.urlparse(url)
    except Exception as e:
        return False, str(e)
    if p.scheme not in ("http", "https"):
        return False, "scheme must be http/https"
    if not p.netloc:
        return False, "missing host"
    host = p.hostname or ""
    if host.lower() not in _LOOPBACK_HOSTS:
        return False, f"wallet_rpc_url must be loopback ({', '.join(sorted(_LOOPBACK_HOSTS))}), got {host}"
    if p.path and p.path != "/json_rpc" and not p.path.endswith("/json_rpc"):
        return False, "path should end with /json_rpc"
    return True, ""

def _validate_wp_url(url):
    if not isinstance(url, str) or not url:
        return False, "empty"
    try:
        p = urllib.parse.urlparse(url)
    except Exception as e:
        return False, str(e)
    if p.scheme not in ("http", "https"):
        return False, "scheme must be http/https"
    if not p.netloc:
        return False, "missing host"
    if p.username or p.password:
        return False, "must not contain credentials"
    if len(url) > 2048:
        return False, "URL too long"
    return True, ""

def validate_config(cfg):
    errors = []
    for k in cfg:
        if k not in _ALLOWED_CONFIG_KEYS:
            errors.append(f"unknown key: {k}")
    def _int_range(key, lo, hi):
        v = cfg.get(key)
        if not isinstance(v, int) or isinstance(v, bool):
            errors.append(f"{key} must be int")
        elif not (lo <= v <= hi):
            errors.append(f"{key} out of range [{lo},{hi}]: {v}")
    def _str_nonempty(key):
        v = cfg.get(key)
        if not isinstance(v, str):
            errors.append(f"{key} must be string")
    _int_range("account_index", 0, 1000000)
    _int_range("poll_interval", 5, 86400)
    _int_range("status_interval", 60, 604800)
    _int_range("min_pool_free", 1, 10000)
    _int_range("batch_size", 1, 200)
    _int_range("address_generation_cooldown", 0, 86400)
    for k in ("wp_post_field", "wp_status_param", "wallet_id"):
        _str_nonempty(k)
        v = cfg.get(k, "")
        if not re.fullmatch(r'[A-Za-z0-9_\-]{1,64}', v):
            errors.append(f"{k} must be 1-64 alphanum/_/-: {v!r}")
    if cfg.get("network") not in ("mainnet", "testnet", "stagenet"):
        errors.append(f"network must be mainnet/testnet/stagenet: {cfg.get('network')!r}")
    if not isinstance(cfg.get("tls_verify"), bool):
        errors.append("tls_verify must be bool")
    if not isinstance(cfg.get("debug"), bool):
        errors.append("debug must be bool")
    servers = cfg.get("servers", [])
    has_servers = isinstance(servers, list) and len(servers) > 0
    if has_servers:
        if cfg.get("wp_url", "") != "" :
            ok, msg = _validate_wp_url(cfg.get("wp_url", ""))
            if not ok:
                errors.append(f"wp_url invalid: {msg}")
    else:
        ok, msg = _validate_wp_url(cfg.get("wp_url", ""))
        if not ok:
            errors.append(f"wp_url invalid: {msg}")
    ok, msg = _validate_wallet_rpc_url(cfg.get("wallet_rpc_url", ""))
    if not ok:
        errors.append(f"wallet_rpc_url invalid: {msg}")
    hex_key = cfg.get("shared_secret_hex", "")
    if has_servers and hex_key == "":
        pass
    elif not isinstance(hex_key, str) or len(hex_key.strip()) != 64:
        errors.append("shared_secret_hex must be 64 hex chars")
    else:
        try:
            bytes.fromhex(hex_key.strip())
        except ValueError:
            errors.append("shared_secret_hex not valid hex")
    sf = cfg.get("state_file", "")
    if not isinstance(sf, str) or not sf or len(sf) > 512 or "\x00" in sf:
        errors.append("state_file invalid")
    elif os.path.isabs(sf):
        pass
    else:
        if ".." in sf.split(os.sep):
            errors.append("state_file must not contain ..")
    for hexk in ("signing_privkey_hex", "signing_pubkey_hex"):
        v = cfg.get(hexk, "")
        if v != "" and (not isinstance(v, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', v.strip())):
            errors.append(f"{hexk} must be 64 hex chars or empty")
    servers = cfg.get("servers", [])
    if servers not in ([], None) and not isinstance(servers, list):
        errors.append("servers must be array")
    elif isinstance(servers, list):
        if len(servers) > 16:
            errors.append("too many servers (max 16)")
        for i, srv in enumerate(servers):
            if not isinstance(srv, dict):
                errors.append(f"servers[{i}] not an object")
                continue
            for k in srv:
                if k not in _ALLOWED_SERVER_KEYS:
                    errors.append(f"servers[{i}] unknown key: {k}")
            url = srv.get("wp_url", "")
            if not isinstance(url, str) or not url:
                errors.append(f"servers[{i}].wp_url missing")
            else:
                ok2, msg2 = _validate_wp_url(url)
                if not ok2:
                    errors.append(f"servers[{i}].wp_url invalid: {msg2}")
            for fk in ("wp_post_field", "wp_status_param"):
                if fk in srv and srv[fk] != "":
                    if not isinstance(srv[fk], str) or not re.fullmatch(r'[A-Za-z0-9_\-]{1,64}', srv[fk]):
                        errors.append(f"servers[{i}].{fk} invalid")
            if "shared_secret_hex" in srv and srv["shared_secret_hex"] != "":
                if not re.fullmatch(r'[0-9a-fA-F]{64}', srv["shared_secret_hex"].strip()):
                    errors.append(f"servers[{i}].shared_secret_hex must be 64 hex")
    return errors

def _config_path_default():
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "xmr-pushd.conf")

def load_config(path=None):
    if path is None:
        path = _config_path_default()

    if not os.path.exists(path):
        die(f"Config file not found: {path}\n"
            "Copy xmr-pushd.conf.example to xmr-pushd.conf and fill in your values.")

    try:
        st = os.stat(path)
        if st.st_mode & (stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
            log(f"Config file {path} is world-readable - chmod 600 recommended", "WARN")
    except Exception:
        pass
    if not os.path.isfile(path):
        die(f"Config path is not a file: {path}")
    if os.path.getsize(path) > 65536:
        die(f"Config file too large (>64KB): {path}")

    try:
        with open(path, "r") as f:
            cfg = json.load(f)
    except json.JSONDecodeError as e:
        die(f"Invalid JSON in {path}: {e}")

    if not isinstance(cfg, dict):
        die(f"Config top-level must be object in {path}")
    if len(cfg) > 50:
        die(f"Config has too many keys ({len(cfg)})")
    for k in cfg:
        if len(str(k)) > 64:
            die(f"Config key too long: {k!r}")

    merged = dict(DEFAULTS)
    for k, v in cfg.items():
        if k in _ALLOWED_CONFIG_KEYS:
            merged[k] = v
        else:
            log(f"Ignoring unknown config key: {k}", "WARN")

    errs = validate_config(merged)
    if errs:
        for e in errs:
            log(f"Config error: {e}", "ERROR")
        die("Config validation failed - fix xmr-pushd.conf")

    if _auto_correct_wallet_port(merged):
        try:
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                raw = json.load(open(path, "r"))
                raw["wallet_rpc_url"] = merged["wallet_rpc_url"]
                json.dump(raw, f, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
            os.chmod(path, 0o600)
            log(f"Config auto-corrected wallet_rpc_url and saved to {path}", "INFO")
        except Exception as e:
            log(f"Failed to persist auto-corrected wallet_rpc_url: {e}", "WARN")

    return merged

# ---------------------------------------------------------------------------
# State persistence (atomic write, bounded, permission 0600)
# ---------------------------------------------------------------------------

def _validate_state_obj(s):
    if not isinstance(s, dict):
        return False
    gi = s.get("generated_indices")
    if not isinstance(gi, list) or len(gi) > MAX_GENERATED_INDICES:
        return False
    for v in gi:
        if not isinstance(v, int) or isinstance(v, bool) or not (0 <= v <= 2000000):
            return False
    ls = s.get("last_seen")
    if not isinstance(ls, dict) or len(ls) > MAX_GENERATED_INDICES:
        return False
    for k, v in ls.items():
        if not isinstance(k, str) or len(k) > 16:
            return False
        if not isinstance(v, dict):
            return False
        if "received" in v and not isinstance(v["received"], (int, float)):
            return False
        if "confs" in v and not isinstance(v["confs"], int):
            return False
        if len(str(v)) > 1024:
            return False
    for k in ("last_status_check", "last_address_push"):
        if k in s and not isinstance(s[k], int):
            return False
    return True

def _resolve_state_path(cfg):
    """Resolve the configured state_file to an absolute path.

    Relative paths are anchored to THIS SCRIPT's directory (same policy as
    the config default), NOT the process working directory. Launching the
    daemon from a different CWD must never silently miss the existing state
    file - a "fresh" state used to trigger a full address-generation batch on
    every start (see check_address_supply).
    """
    path = cfg.get("state_file")
    if not isinstance(path, str) or not path or len(path) > 512 or "\x00" in path:
        log("state_file setting invalid - falling back to default", "WARN")
        path = DEFAULTS["state_file"]
    if os.path.isabs(path):
        return os.path.normpath(path)
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.normpath(os.path.join(base, path))

def load_state(cfg):
    path = _resolve_state_path(cfg)
    if os.path.exists(path):
        if os.path.getsize(path) > 1024 * 1024:
            log(f"State file too large (>1MB) at {path}, starting fresh", "WARN")
        else:
            try:
                with open(path, "r") as f:
                    raw = f.read(1024 * 1024)
                    s = json.loads(raw)
                if not isinstance(s, dict):
                    raise ValueError("state is not a dict")
                if not _validate_state_obj(s):
                    raise ValueError("state failed schema validation")
                s.setdefault("generated_indices", [])
                s.setdefault("last_seen", {})
                s.setdefault("last_status_check", 0)
                s.setdefault("last_address_push", 0)
                s.setdefault("server_offset", 0)
                if not isinstance(s.get("active_watch"), list):
                    s["active_watch"] = []
                s["generated_indices"] = sorted(set(int(x) for x in s["generated_indices"] if isinstance(x, int) and 0 <= x <= 2000000))[:MAX_GENERATED_INDICES]
                s["last_seen"] = {str(k): v for k, v in s["last_seen"].items() if isinstance(k, str) and len(k) < 16}
                return s
            except (json.JSONDecodeError, IOError, ValueError) as e:
                log(f"Corrupt state file at {path} ({e}), starting fresh", "WARN")

    return {
        "generated_indices": [],
        "last_seen": {},
        "last_status_check": 0,
        "last_address_push": 0,
        "server_offset": 0,
        "active_watch": [],
    }

def save_state(state, cfg):
    if not isinstance(state, dict):
        log(f"save_state got non-dict state ({type(state).__name__}) - not saving", "ERROR")
        return False
    if not _validate_state_obj(state):
        log("save_state state failed validation - not saving to avoid corrupting file", "ERROR")
        return False
    path = _resolve_state_path(cfg)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w") as f:
            json.dump(state, f, separators=(',', ':'))
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
    except (IOError, OSError, TypeError, ValueError) as e:
        log(f"Failed to write state tmp file {tmp}: {e}", "ERROR")
        log("State file directory must be writable - run with sudo on Linux/Termux, or launch the shell as Administrator on Windows", "HINT")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False
    try:
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    except (IOError, OSError) as e:
        log(f"Failed to atomically replace state file {path}: {e}", "ERROR")
        return False
    debug(f"State saved ({len(state['generated_indices'])} indices tracked)")
    return True

# ---------------------------------------------------------------------------
# Crypto (secretbox via pynacl) - bounded
# ---------------------------------------------------------------------------

def crypto_init(cfg):
    hex_key = cfg["shared_secret_hex"].strip()
    if not hex_key:
        return None
    if len(hex_key) != 64:
        die(f"shared_secret_hex must be exactly 64 hex chars (got {len(hex_key)}).")
    if not re.fullmatch(r'[0-9a-fA-F]{64}', hex_key):
        die("shared_secret_hex must be hex [0-9a-f].")
    try:
        key = bytes.fromhex(hex_key)
    except ValueError:
        die("shared_secret_hex is not valid hex.")
    if len(key) != 32:
        die("shared_secret_hex must decode to 32 bytes.")
    debug("SecretBox initialized")
    return SecretBox(key)

def _get_signing_key(cfg):
    priv = (cfg.get("signing_privkey_hex") or "").strip().lower()
    if not priv or len(priv) != 64 or not re.fullmatch(r'[0-9a-f]{64}', priv):
        return None
    try:
        return SigningKey(bytes.fromhex(priv))
    except Exception as e:
        log(f"signing_privkey invalid: {e}", "ERROR")
        return None

def _get_server_list(cfg):
    servers = cfg.get("servers")
    if isinstance(servers, list) and servers:
        out = []
        for srv in servers:
            if not isinstance(srv, dict):
                continue
            url = (srv.get("wp_url") or "").strip()
            sec = (srv.get("shared_secret_hex") or cfg.get("shared_secret_hex") or "").strip()
            if not url or not sec:
                continue
            out.append({
                "wp_url": url.rstrip("/"),
                "wp_post_field": srv.get("wp_post_field") or cfg.get("wp_post_field") or "msg",
                "wp_status_param": srv.get("wp_status_param") or cfg.get("wp_status_param") or "t",
                "shared_secret_hex": sec,
                "label": srv.get("label") or url,
                "pinned_kx_pk": (srv.get("pinned_kx_pk") or "").strip().lower(),
            })
        if out:
            return out
    return [{
        "wp_url": cfg["wp_url"].rstrip("/"),
        "wp_post_field": cfg.get("wp_post_field", "msg"),
        "wp_status_param": cfg.get("wp_status_param", "t"),
        "shared_secret_hex": cfg["shared_secret_hex"],
        "label": "default",
        "pinned_kx_pk": "",
    }]

def _ensure_signing_keys(cfg, config_path):
    priv = (cfg.get("signing_privkey_hex") or "").strip().lower()
    pub = (cfg.get("signing_pubkey_hex") or "").strip().lower()
    need_gen = False
    sk = None
    if priv and pub and len(priv) == 64 and len(pub) == 64:
        try:
            sk = SigningKey(bytes.fromhex(priv))
            derived = sk.verify_key.encode(encoder=HexEncoder).decode("ascii").lower()
            if derived != pub:
                log(f"signing keypair mismatch (derived {derived[:8]}.. != stored {pub[:8]}..) - regenerating", "WARN")
                need_gen = True
            else:
                return sk
        except Exception as e:
            log(f"signing keys invalid ({e}) - regenerating", "WARN")
            need_gen = True
    else:
        need_gen = True
    if need_gen:
        try:
            sk = SigningKey.generate()
            priv_hex = sk.encode(encoder=HexEncoder).decode("ascii").lower()
            pub_hex = sk.verify_key.encode(encoder=HexEncoder).decode("ascii").lower()
        except Exception as e:
            die(f"Failed to generate Ed25519 keypair: {e}")
        cfg["signing_privkey_hex"] = priv_hex
        cfg["signing_pubkey_hex"] = pub_hex
        log(f"Generated new Ed25519 keypair - pubkey {pub_hex[:16]}... (private stays on device, never leaves)", "INFO")
        log(f"Add this public key to WordPress → Settings → Monero Push → Authorized Devices (or scan QR).", "INFO")
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    raw = json.load(f)
                raw["signing_privkey_hex"] = priv_hex
                raw["signing_pubkey_hex"] = pub_hex
                tmp = config_path + ".tmp"
                with open(tmp, "w") as tf:
                    json.dump(raw, tf, indent=2)
                os.chmod(tmp, 0o600)
                os.replace(tmp, config_path)
                os.chmod(config_path, 0o600)
                log(f"Signing keys persisted to {config_path} (0600)", "INFO")
            except Exception as e:
                log(f"Failed to persist signing keys to {config_path}: {e}", "WARN")
        return sk
    return None

def encrypt(plaintext_str, box):
    if not isinstance(plaintext_str, str):
        log("encrypt got non-string plaintext", "ERROR")
        return None
    raw = plaintext_str.encode("utf-8")
    if len(raw) > MAX_DECRYPTED_BYTES:
        log(f"encrypt plaintext too large ({len(raw)} > {MAX_DECRYPTED_BYTES})", "ERROR")
        return None
    try:
        ciphertext = box.encrypt(plaintext_str.encode("utf-8"), encoder=RawEncoder)
    except Exception as e:
        log(f"encrypt failed: {_sanitize_log_str(str(e))}", "ERROR")
        return None
    nonce = ciphertext[:box.NONCE_SIZE]
    ct = ciphertext[box.NONCE_SIZE:]
    if len(nonce) != box.NONCE_SIZE:
        log("encrypt nonce size mismatch", "ERROR")
        return None
    try:
        return base64.urlsafe_b64encode(nonce + ct).decode("ascii").rstrip("=")
    except Exception as e:
        log(f"encrypt b64 failed: {e}", "ERROR")
        return None

def decrypt(encoded_str, box):
    if not isinstance(encoded_str, str):
        debug("decrypt got non-string input")
        return None
    encoded_str = encoded_str.strip()
    if len(encoded_str) == 0 or len(encoded_str) > MAX_ENCRYPTED_B64_CHARS:
        debug(f"decrypt: bad b64 length {len(encoded_str)}")
        return None
    if not re.fullmatch(r'[A-Za-z0-9_\-]*={0,3}', encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4)):
        if not re.fullmatch(r'[A-Za-z0-9_\-]+', encoded_str):
            debug("decrypt: b64 charset invalid")
            return None
    try:
        padded = encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded)
        if len(raw) > MAX_DECRYPTED_BYTES + 64:
            debug(f"decrypt: raw too large {len(raw)}")
            return None
        if len(raw) < box.NONCE_SIZE:
            debug("decrypt: payload too short")
            return None
        nonce = raw[:box.NONCE_SIZE]
        ct = raw[box.NONCE_SIZE:]
        if len(ct) < 16:
            debug("decrypt: ciphertext too short")
            return None
        pt = box.decrypt(ct, nonce, encoder=RawEncoder).decode("utf-8")
        if len(pt.encode("utf-8")) > MAX_DECRYPTED_BYTES:
            debug("decrypt: plaintext too large")
            return None
        return pt
    except Exception as e:
        debug(f"decrypt failed: {_sanitize_log_str(str(e))}")
        return None

# ---------------------------------------------------------------------------
# Wallet RPC (local loopback only, via curl + digest auth) - hardened
# ---------------------------------------------------------------------------

def _sanitize_curl_arg(s):
    if not isinstance(s, str):
        s = str(s)
    if len(s) > 2048:
        s = s[:2048]
    if "\x00" in s or "\n" in s or "\r" in s:
        raise ValueError("curl arg contains control chars")
    return s

def rpc_call(method, params, cfg):
    if not isinstance(method, str) or not re.fullmatch(r'[A-Za-z0-9_]{1,64}', method):
        log(f"rpc_call got invalid method {method!r}", "ERROR")
        return None
    if not isinstance(params, dict):
        log("rpc_call params not dict", "ERROR")
        return None
    url = cfg["wallet_rpc_url"]
    ok, msg = _validate_wallet_rpc_url(url)
    if not ok:
        log(f"rpc_call wallet_rpc_url invalid: {msg}", "ERROR")
        return None
    user = cfg["wallet_rpc_user"]
    passwd = cfg["wallet_rpc_pass"]
    if not isinstance(user, str) or len(user) > 256:
        log("wallet_rpc_user invalid", "ERROR")
        return None
    if not isinstance(passwd, str) or len(passwd) > 512:
        log("wallet_rpc_pass invalid", "ERROR")
        return None
    if "\x00" in user or "\x00" in passwd or "\n" in user or "\n" in passwd:
        log("wallet credentials contain control chars", "ERROR")
        return None

    try:
        payload = json.dumps({"jsonrpc": "2.0", "id": "0", "method": method, "params": params}, separators=(',', ':'))
    except (TypeError, ValueError) as e:
        log(f"rpc_call json dump failed for {method}: {e}", "ERROR")
        return None
    if len(payload) > 65536:
        log(f"rpc_call payload too large for {method}", "ERROR")
        return None
    try:
        payload = _sanitize_curl_arg(payload)
        url = _sanitize_curl_arg(url)
    except ValueError as e:
        log(f"rpc_call sanitize failed: {e}", "ERROR")
        return None

    cmd = ["curl", "-s", "-X", "POST", url,
           "-H", "Content-Type: application/json",
           "-d", payload,
           "--connect-timeout", "10",
           "--max-time", "30",
           "--proto", "=http,https",
           "--fail-with-body"]

    if user:
        cmd += ["--digest", "-u", f"{user}:{passwd}"]

    debug(f"RPC → {method}({json.dumps(params, separators=(',', ':'))[:300]})")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
    except subprocess.TimeoutExpired:
        log(f"RPC {method} timed out after 35s", "WARN")
        return None
    except Exception as e:
        log(f"RPC {method} subprocess failed: {_sanitize_log_str(str(e))}", "WARN")
        return None

    if result.returncode != 0 or not result.stdout.strip():
        err = _sanitize_log_str(result.stderr.strip() or "empty response", 400)
        log(f"RPC {method} curl error (exit {result.returncode}): {err}", "WARN")
        return None
    if len(result.stdout) > 1024 * 1024:
        log(f"RPC {method} response too large ({len(result.stdout)} bytes)", "WARN")
        return None

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        snippet = _sanitize_log_str(result.stdout[:200].replace("\n", " "), 200)
        log(f"RPC {method} non-JSON response: {snippet}", "WARN")
        return None

    if not isinstance(data, dict):
        log(f"RPC {method} response not object", "WARN")
        return None
    if len(data) > 20:
        log(f"RPC {method} response too many keys", "WARN")
        return None

    if "error" in data:
        err = data["error"]
        if isinstance(err, dict):
            msg = _sanitize_log_str(str(err.get('message', err)), 300)
            code = err.get('code', '?')
        else:
            msg = _sanitize_log_str(str(err), 300)
            code = '?'
        log(f"RPC {method} error: {msg} (code: {code})", "WARN")
        return None

    res = data.get("result", {})
    if res is not None and not isinstance(res, dict):
        log(f"RPC {method} result not object: {type(res).__name__}", "WARN")
        return None
    return res if isinstance(res, dict) else {}

# ---------------------------------------------------------------------------
# HTTP helpers - hardened: size caps, no redirects, strict headers
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, f"Redirect blocked ({code} -> {newurl})", headers, fp)

def _ssl_context(cfg):
    if not cfg.get("tls_verify", True):
        debug("TLS verification DISABLED (LAN testing)")
        try:
            ctx = ssl._create_unverified_context()
            ctx.options |= getattr(ssl, 'OP_NO_SSLv2', 0) | getattr(ssl, 'OP_NO_SSLv3', 0)
            return ctx
        except Exception as e:
            log(f"Failed to create unverified SSL context: {e}", "WARN")
            return ssl._create_unverified_context()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.options |= getattr(ssl, 'OP_NO_SSLv2', 0) | getattr(ssl, 'OP_NO_SSLv3', 0)
        return ctx
    except Exception as e:
        log(f"Failed to create SSL context: {e}", "WARN")
        return None

def _read_capped(fp, limit=MAX_HTTP_RESPONSE_BYTES):
    chunks = []
    total = 0
    while True:
        chunk = fp.read(8192)
        if not chunk:
            break
        total += len(chunk)
        if total > limit:
            raise ValueError(f"response exceeded {limit} bytes")
        chunks.append(chunk)
    return b"".join(chunks)

def _build_opener(cfg):
    ctx = _ssl_context(cfg)
    handlers = [_NoRedirect()]
    if ctx is not None:
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    return urllib.request.build_opener(*handlers)

def _http_post(url, data, cfg, ack_marker=None):
    if not isinstance(url, str) or len(url) > 2048:
        log("POST url invalid", "ERROR")
        return None
    if not isinstance(data, str) or len(data) > 65536:
        log("POST data too large/invalid", "ERROR")
        return None
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        log(f"POST url bad scheme: {p.scheme}", "ERROR")
        return None
    opener = _build_opener(cfg)
    req = urllib.request.Request(url, data=data.encode("utf-8"), method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "xmr-pushd/1.0", "Accept": "text/plain,*/*"})
    debug(f"POST → {url}")
    try:
        with opener.open(req, timeout=30) as resp:
            if resp.status not in (200, 204):
                log(f"POST HTTP {resp.status}", "WARN")
                return None
            ctype = resp.headers.get("Content-Type", "")
            if ctype and "text/html" not in ctype and "text/plain" not in ctype and "application" not in ctype and ctype != "":
                debug(f"POST unexpected Content-Type: {ctype}")
            clen = resp.headers.get("Content-Length")
            if clen is not None:
                try:
                    if int(clen) > MAX_HTTP_RESPONSE_BYTES:
                        log(f"POST Content-Length too large: {clen}", "WARN")
                        return None
                except ValueError:
                    pass
            body = _read_capped(resp, MAX_HTTP_RESPONSE_BYTES)
            ctype = (resp.headers.get("Content-Type", "") or "").lower()
            head = body[:400].decode("utf-8", errors="ignore").lower()
            if ("html" in ctype or "<html" in head or "<!doctype" in head):
                # The push endpoint (class-wc-xmr-push-endpoint.php respond_ok())
                # deliberately returns this exact generic "Thank you for your
                # message." HTML page for EVERY outcome - success, decrypt
                # failure, bad field - so a scanner probing the endpoint can't
                # tell success from failure by content. That's intentional and
                # is NOT the same signal as "a caching layer/WAF/wrong URL
                # served us the site's real homepage instead of the plugin."
                # Only treat this as a hard failure if it does NOT match the
                # known ack the caller told us to expect.
                if ack_marker is not None and ack_marker in body:
                    debug(f"POST ← HTTP {resp.status} ({len(body)} bytes) - matched expected ack page")
                    return body
                log("POST returned an HTML page (HTTP " + str(resp.status) +
                    ", Content-Type: " + (resp.headers.get("Content-Type", "") or "unknown") +
                    ") - the push did NOT reach the plugin handler. "
                    "Check the plugin is active, wp_url is correct, and no "
                    "WAF/redirect/cache layer is intercepting. Body preview: " +
                    _sanitize_log_str(body[:160].decode("utf-8", errors="ignore"), 300), "WARN")
                return None
            debug(f"POST ← HTTP {resp.status} ({len(body)} bytes)")
            return body
    except ValueError as e:
        log(f"POST too large: {e}", "WARN")
        return None
    except urllib.error.HTTPError as e:
        log(f"POST HTTP {e.code}: {_sanitize_log_str(str(e.reason), 200)}", "WARN")
        return None
    except urllib.error.URLError as e:
        log(f"POST connection error: {_sanitize_log_str(str(e.reason), 300)}", "WARN")
        return None
    except Exception as e:
        log(f"POST unexpected: {_sanitize_log_str(str(e), 300)}", "WARN")
        return None

def _http_get(url, cfg):
    if not isinstance(url, str) or len(url) > 4096:
        log("GET url invalid", "ERROR")
        return None
    p = urllib.parse.urlparse(url)
    if p.scheme not in ("http", "https"):
        log(f"GET url bad scheme: {p.scheme}", "ERROR")
        return None
    ctx = _ssl_context(cfg)
    debug(f"GET → {url[:120]}...")
    opener = _build_opener(cfg)
    try:
        with opener.open(url, timeout=30) as resp:
            if resp.status != 200:
                log(f"GET HTTP {resp.status}", "WARN")
                return None
            clen = resp.headers.get("Content-Length")
            if clen is not None:
                try:
                    if int(clen) > MAX_HTTP_RESPONSE_BYTES:
                        log(f"GET Content-Length too large: {clen}", "WARN")
                        return None
                except ValueError:
                    pass
            body = _read_capped(resp, MAX_HTTP_RESPONSE_BYTES)
            try:
                text = body.decode("utf-8", errors="strict").strip()
            except UnicodeDecodeError:
                log("GET body not valid UTF-8", "WARN")
                return None
            if len(text) > MAX_HTTP_RESPONSE_BYTES:
                log("GET decoded body too large", "WARN")
                return None
            ctype = (resp.headers.get("Content-Type", "") or "").lower()
            if ("html" in ctype
                    or "<html" in text[:400].lower()
                    or "<!doctype" in text[:400].lower()):
                log("Status GET returned an HTML page (Content-Type: " +
                    (resp.headers.get("Content-Type", "") or "unknown") +
                    ", HTTP " + str(resp.status) + ") instead of the plugin's encrypted response. "
                    "The request did NOT reach the plugin handler - WordPress served a normal page "
                    "(front page, 404, maintenance, or a security-plugin block). Check the plugin is active "
                    "on that site, wp_url points to the site root (no /wp-admin, /wp-json, or trailing path), "
                    "and no redirect/.htaccess/WAF/cache layer is intercepting. "
                    "Body preview: " + _sanitize_log_str(text[:160], 300), "WARN")
                return None
            # The status endpoint returns ONLY a base64url-encrypted blob.
            # Anything else - JSON error, plain-text WAF block ("Blocked by
            # Wordfence"), nginx "502 Bad Gateway", XML, PHP fatal dump - means
            # the request never produced a valid response the device can
            # decrypt, so catch the wrong SHAPE here and say what the server
            # actually said instead of a cryptic "decrypt failed" later.
            stripped = text.lstrip()
            if len(stripped) >= 16 and re.fullmatch(r'[A-Za-z0-9_\-]+={0,2}', stripped):
                debug(f"GET ← HTTP {resp.status} ({len(text)} bytes)")
                return stripped
            if len(stripped) >= 1 and stripped[:1] in ("{", "["):
                log("Status GET returned a JSON response from the plugin: " +
                    _sanitize_log_str(stripped[:300], 400) + " (HTTP " +
                    str(resp.status) + "). The plugin received the request but "
                    "rejected/errored it - check the device clock is within 5 "
                    "minutes of the server and that wallet_id matches the "
                    "server's settings.", "WARN")
                return None
            log("Status GET returned unexpected content (Content-Type: " +
                (resp.headers.get("Content-Type", "") or "unknown") +
                ", HTTP " + str(resp.status) + ") instead of the plugin's encrypted response: " +
                _sanitize_log_str(text[:160], 300) + " - expected a base64url blob. "
                "The request was intercepted or the plugin isn't handling it. "
                "Check the plugin is active, wp_url points to the site root, and no "
                "WAF/security plugin/redirect is blocking the path.", "WARN")
            return None
    except ValueError as e:
        log(f"GET too large: {e}", "WARN")
        return None
    except urllib.error.HTTPError as e:
        log(f"GET HTTP {e.code}: {_sanitize_log_str(str(e.reason), 200)}", "WARN")
        return None
    except urllib.error.URLError as e:
        log(f"GET connection error: {_sanitize_log_str(str(e.reason), 300)}", "WARN")
        return None
    except Exception as e:
        log(f"GET unexpected: {_sanitize_log_str(str(e), 300)}", "WARN")
        return None

# ---------------------------------------------------------------------------
# WordPress push (confirmation or address batch) - bounded
# ---------------------------------------------------------------------------

def _sign_payload(payload_json, signing_key):
    if signing_key is None:
        return None, None
    try:
        sig = signing_key.sign(payload_json.encode("utf-8"))
        pk_hex = signing_key.verify_key.encode(encoder=HexEncoder).decode("ascii").lower()
        sig_hex = sig.signature.hex().lower()
        return pk_hex, sig_hex
    except Exception as e:
        log(f"signing failed: {e}", "ERROR")
        return None, None

def wp_push(payload_obj, cfg, box):
    if not isinstance(payload_obj, dict):
        log("wp_push got non-dict payload", "ERROR")
        return False
    if len(payload_obj) > 20:
        log("wp_push payload too many keys", "ERROR")
        return False
    try:
        payload_json = json.dumps(payload_obj, separators=(',', ':'))
    except (TypeError, ValueError) as e:
        log(f"wp_push json dump failed: {e}", "ERROR")
        return False
    if len(payload_json.encode("utf-8")) > MAX_DECRYPTED_BYTES:
        log(f"wp_push payload too large ({len(payload_json)} chars)", "ERROR")
        return False
    debug(f"Encrypting push payload ({len(payload_json)} bytes): {_sanitize_log_str(payload_json[:200], 300)}")
    encrypted = encrypt(payload_json, box)
    if not encrypted:
        log("Encryption failed for push", "ERROR")
        return False
    if len(encrypted) > MAX_ENCRYPTED_B64_CHARS:
        log("Encrypted push too large", "ERROR")
        return False

    signing_key = cfg.get("_signing_key")
    pk_hex, sig_hex = _sign_payload(payload_json, signing_key)
    if signing_key is not None and sig_hex:
        try:
            debug(f"Signing push with pk {pk_hex[:8]}...")
        except Exception:
            pass
        try:
            data = urllib.parse.urlencode({cfg["wp_post_field"]: encrypted, "sig": sig_hex, "pk": pk_hex})
        except Exception as e:
            log(f"wp_push urlencode failed: {e}", "ERROR")
            return False
    else:
        try:
            data = urllib.parse.urlencode({cfg["wp_post_field"]: encrypted})
        except Exception as e:
            log(f"wp_push urlencode failed: {e}", "ERROR")
            return False
    if len(data) > 65536:
        log("wp_push POST data too large", "ERROR")
        return False
    url = cfg["wp_url"].rstrip("/") + "/"
    ok, _ = _validate_wp_url(url)
    if not ok:
        log(f"wp_push wp_url invalid: {url}", "ERROR")
        return False

    # class-wc-xmr-push-endpoint.php respond_ok() always returns this exact
    # generic HTML page on the push endpoint - for success AND for internal
    # failures like decrypt_fail - by design, so an outside scanner can't
    # distinguish outcomes from the response body. Tell _http_post to treat
    # that specific page as an ack rather than "wrong URL/WAF/cache page".
    body = _http_post(url, data, cfg, ack_marker=b"Thank you for your message.")
    if body is None:
        return False
    if len(body) > 4096:
        log(f"wp_push response unexpectedly large ({len(body)} bytes)", "WARN")
    return True

# ---------------------------------------------------------------------------
# WordPress status blob - strictly validated
# ---------------------------------------------------------------------------

WC_STATUS_CONSISTENCY_WINDOW = 10
_last_status_snapshots = []

def _check_status_consistency(burn_rate, pool_free):
    global _last_status_snapshots
    try:
        burn_rate = float(burn_rate) if burn_rate is not None else 0.0
    except Exception:
        return
    pool_free = int(pool_free) if isinstance(pool_free, int) else 0
    now = int(time.time())
    _last_status_snapshots.append((now, burn_rate, pool_free))
    cutoff = now - 3600
    _last_status_snapshots = [(t, b, p) for (t, b, p) in _last_status_snapshots if t >= cutoff]
    if len(_last_status_snapshots) < 3:
        return
    avg_burn = sum(b for (_, b, _) in _last_status_snapshots[:-1]) / max(1, len(_last_status_snapshots) - 1)
    if avg_burn > 0 and burn_rate > avg_burn * 5 and burn_rate > 10:
        log(f"Status sanity: burn_rate spike {burn_rate:.1f}/h vs avg {avg_burn:.1f}/h - possible malicious low-pool claim, not acting on burn alone", "WARN")
    if len(_last_status_snapshots) >= 4:
        drops = [prev_p - cur_p for (_, _, prev_p), (_, _, cur_p) in zip(_last_status_snapshots[-4:-1], _last_status_snapshots[-3:])]
        if all(d > 20 for d in drops) and pool_free < 5:
            log(f"Status sanity: rapid pool drain {drops} - flagging for manual review", "WARN")

def _validate_status_response(data):
    if not isinstance(data, dict):
        return False, "not an object"
    if len(data) > MAX_JSON_KEYS + 2:
        return False, "too many keys"
    if data.get("v") != 1:
        return False, f"bad v: {data.get('v')!r}"
    ts = data.get("ts")
    if not isinstance(ts, int) or isinstance(ts, bool):
        return False, "ts not int"
    now = int(time.time())
    if abs(ts - now) > 600:
        return False, f"ts drift too large ({ts} vs {now})"
    allowed = {"v", "ts", "network", "pool_free", "pool_total", "reserved_count", "detected_count", "burn_rate_24h", "active_indices", "request_log"}
    for k in data:
        if k not in allowed:
            return False, f"unexpected key: {k}"
    net = data.get("network")
    if net is not None and net not in ("mainnet", "testnet", "stagenet"):
        return False, f"bad network: {net!r}"
    for field in ("pool_free", "pool_total", "reserved_count", "detected_count"):
        v = data.get(field)
        if v is None:
            continue
        if not isinstance(v, int) or isinstance(v, bool):
            return False, f"{field} not int: {v!r}"
        if not (0 <= v <= MAX_POOL_VALUE):
            return False, f"{field} out of range: {v}"
    burn = data.get("burn_rate_24h")
    if burn is not None and not isinstance(burn, (int, float)):
        return False, "burn_rate_24h not numeric"
    if isinstance(burn, float) and (burn != burn or burn in (float('inf'), float('-inf'))):
        return False, "burn_rate_24h NaN/inf"
    if isinstance(burn, (int, float)) and not (0 <= float(burn) <= MAX_BURN_RATE):
        return False, f"burn_rate out of range: {burn}"
    ai = data.get("active_indices")
    if ai is not None:
        if not isinstance(ai, list):
            return False, "active_indices not list"
        if len(ai) > MAX_ACTIVE_INDICES:
            return False, f"active_indices too long ({len(ai)})"
        seen = set()
        for i, v in enumerate(ai):
            if not isinstance(v, int) or isinstance(v, bool):
                return False, f"active_indices[{i}] not int"
            if not (0 <= v <= 2000000):
                return False, f"active_indices[{i}] out of range: {v}"
            if v in seen:
                return False, f"active_indices duplicate: {v}"
            seen.add(v)
        if ai != sorted(ai):
            return False, "active_indices not sorted"
    req_log = data.get("request_log")
    if req_log is not None and not isinstance(req_log, bool):
        return False, "request_log not bool"
    pool_free = data.get("pool_free")
    pool_total = data.get("pool_total")
    if isinstance(pool_free, int) and isinstance(pool_total, int) and pool_total > 0 and pool_free > pool_total:
        return False, f"pool_free {pool_free} > pool_total {pool_total}"
    return True, ""

def server_now(state):
    """Current time adjusted by the measured server clock offset.

    The server rejects any push whose ts drifts more than 300s from its own
    clock - and it always answers with the same generic HTTP page, so the
    daemon cannot tell a rejected push from an accepted one. An Android
    device without NTP (airplane mode, battery pull, Termux wakelock
    quirks) drifts past that window easily, after which EVERY confirmation
    push is silently dropped while this daemon still logs "Pushed: ..."
    success - payments arrive but orders never update.

    check_address_supply() measures the offset from every authenticated
    status response (server 'ts' minus local receive time) and stores it in
    state["server_offset"]. All outgoing payload timestamps go through this
    helper, so a drifting device self-corrects on the first successful
    status check instead of going dark.
    """
    try:
        off = state.get("server_offset", 0) if isinstance(state, dict) else 0
    except Exception:
        off = 0
    if not isinstance(off, int) or isinstance(off, bool) or not (-600 <= off <= 600):
        off = 0
    return int(time.time()) + off


def wp_status(cfg, box, ts=None):
    req_obj = {
        "v": 1,
        "ts": int(ts) if isinstance(ts, int) and not isinstance(ts, bool) else int(time.time()),
        "type": "status_request",
        "network": cfg["network"],
        "wallet_id": cfg["wallet_id"],
    }
    if not isinstance(req_obj["wallet_id"], str) or len(req_obj["wallet_id"]) > 64 or not re.fullmatch(r'[A-Za-z0-9_\-]{1,64}', req_obj["wallet_id"]):
        log(f"wp_status wallet_id invalid: {req_obj['wallet_id']!r}", "ERROR")
        return None
    try:
        req_json = json.dumps(req_obj, separators=(',', ':'))
    except (TypeError, ValueError) as e:
        log(f"wp_status json dump failed: {e}", "ERROR")
        return None
    encrypted = encrypt(req_json, box)
    if not encrypted:
        log("Encryption failed for status request", "ERROR")
        return None
    if len(encrypted) > 4096:
        log("Encrypted status request too large", "ERROR")
        return None

    url = cfg["wp_url"].rstrip("/") + "/?" + urllib.parse.urlencode({cfg["wp_status_param"]: encrypted})
    if len(url) > 4096:
        log("Status request URL too long", "ERROR")
        return None
    debug(f"Requesting pool status...")

    body = _http_get(url, cfg)
    if not body:
        return None
    if len(body) > MAX_ENCRYPTED_B64_CHARS:
        log(f"Status response too large ({len(body)} chars)", "WARN")
        return None
    plaintext = decrypt(body, box)
    if not plaintext:
        log(f"Status response decryption failed (body head: {body[:60]!r}). "
            "The server did not return a blob decryptable with the current "
            "shared secret. Re-run pairing (--pair) to refresh the shared "
            "secret, and confirm the WordPress plugin's key wasn't regenerated "
            "or the server reinstalled.", "WARN")
        return None
    debug(f"Status plaintext: {_sanitize_log_str(plaintext[:500], 500)}")
    if len(plaintext) > MAX_DECRYPTED_BYTES:
        log(f"Status plaintext too large ({len(plaintext)})", "WARN")
        return None
    if len(plaintext) == 0:
        log("Status plaintext empty", "WARN")
        return None

    try:
        data = json.loads(plaintext)
    except json.JSONDecodeError as e:
        log(f"Status response not valid JSON after decryption: {_sanitize_log_str(str(e), 200)}", "WARN")
        return None

    ok, reason = _validate_status_response(data)
    if not ok:
        global _consecutive_invalid
        _consecutive_invalid += 1
        log(f"Status response failed validation: {reason} - raw: {_sanitize_log_str(plaintext[:300], 400)}", "WARN")
        if _consecutive_invalid >= CONSECUTIVE_INVALID_THRESHOLD:
            log(f"Status validation failed {_consecutive_invalid} times in a row - possible server compromise or misconfig, backing off", "ERROR")
        return None
    _consecutive_invalid = 0
    _check_status_consistency(data.get("burn_rate_24h"), data.get("pool_free"))

    return data

# ---------------------------------------------------------------------------
# Address generation (local wallet-rpc create_address)
# ---------------------------------------------------------------------------

def generate_addresses(count, state, cfg):
    if not isinstance(count, int) or isinstance(count, bool) or not (1 <= count <= 200):
        log(f"generate_addresses called with invalid count ({count!r}) - aborting", "ERROR")
        return []
    if not isinstance(state, dict) or "generated_indices" not in state:
        log("generate_addresses got invalid state (no generated_indices) - aborting", "ERROR")
        return []
    if len(state["generated_indices"]) >= MAX_GENERATED_INDICES:
        log(f"Address pool at cap ({MAX_GENERATED_INDICES}) - not generating more", "WARN")
        return []
    count = min(count, MAX_GENERATED_INDICES - len(state["generated_indices"]))
    account = cfg["account_index"]
    if not isinstance(account, int) or isinstance(account, bool) or not (0 <= account <= 1000000):
        log(f"generate_addresses got invalid account_index ({account!r}) - aborting", "ERROR")
        return []
    new_indices = []
    addresses = []

    log(f"Generating {count} subaddresses on account {account}...")

    for i in range(count):
        if len(state["generated_indices"]) + len(new_indices) >= MAX_GENERATED_INDICES:
            log("Hit generated_indices cap mid-batch, stopping", "WARN")
            break
        label = f"wc-push-{int(time.time())}-{i}"
        if len(label) > 64 or not re.fullmatch(r'[A-Za-z0-9_\-]+', label):
            label = f"wc-push-{i}"
        try:
            res = rpc_call("create_address", {"account_index": account, "label": label}, cfg)
        except Exception as e:
            log(f"create_address threw at {i}/{count}: {_sanitize_log_str(str(e), 300)}", "ERROR")
            break
        if not res or "address" not in res:
            log(f"create_address failed at {i}/{count}, stopping batch", "ERROR")
            break
        if not isinstance(res["address"], str) or not res["address"]:
            log(f"create_address returned non-string/empty address at {i}/{count}: {_sanitize_log_str(repr(res), 300)}", "ERROR")
            break
        if len(res["address"]) > 256 or len(res["address"]) < 90:
            log(f"create_address returned bad-length address at {i}/{count}: {len(res['address'])}", "ERROR")
            break
        if not re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{90,256}', res["address"]):
            log(f"create_address returned non-base58 address at {i}/{count}", "ERROR")
            break
        try:
            idx = int(res.get("address_index", 0))
        except (TypeError, ValueError) as e:
            log(f"create_address returned non-int address_index at {i}/{count}: {res.get('address_index')!r} - {e}", "ERROR")
            break
        if not (0 <= idx <= 2000000):
            log(f"create_address returned out-of-range index at {i}/{count}: {idx}", "ERROR")
            break
        addr = res["address"]
        new_indices.append(idx)
        addresses.append({"address": addr, "index": idx})

    if new_indices:
        log(f"Generated {len(new_indices)} addresses (indices {new_indices[0]}-{new_indices[-1]})")

        for i in new_indices:
            if i not in state["generated_indices"]:
                state["generated_indices"].append(i)
        state["generated_indices"] = sorted(set(state["generated_indices"]))[:MAX_GENERATED_INDICES]

    return addresses

# ---------------------------------------------------------------------------
# Confirmation polling (the main loop work)
# ---------------------------------------------------------------------------

def poll_confirmations(state, cfg, box):
    if not isinstance(state, dict) or "generated_indices" not in state:
        log("poll_confirmations got invalid state", "ERROR")
        return
    indices = state["generated_indices"]
    if not isinstance(indices, list):
        log("poll_confirmations generated_indices not a list", "ERROR")
        return
    indices = [int(x) for x in indices if isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 2000000][:MAX_GENERATED_INDICES]
    if not indices:
        debug("No generated indices yet - skipping confirmation poll")
        return

    account = cfg["account_index"]
    if not isinstance(account, int) or isinstance(account, bool) or not (0 <= account <= 1000000):
        log(f"poll_confirmations bad account_index {account!r}", "ERROR")
        return
    debug(f"Polling {len(indices)} subaddress indices: {indices[:10]}{'...' if len(indices) > 10 else ''}")

    # Force the wallet to sync with the daemon right now instead of relying
    # solely on wallet-rpc's own background auto-refresh thread. That thread
    # runs on its own timer independent of poll_interval, and on Android it
    # can stall or get throttled while Termux is backgrounded/screen is off
    # - so without this, get_transfers below may just be re-reading a stale
    # view. Best-effort: if it fails/times out we still poll with whatever
    # the wallet already has, same as before.
    refresh_res = rpc_call("refresh", {}, cfg)
    if isinstance(refresh_res, dict):
        blocks_fetched = refresh_res.get("blocks_fetched")
        if isinstance(blocks_fetched, int) and blocks_fetched > 0:
            debug(f"refresh pulled {blocks_fetched} new block(s) before polling")
    else:
        debug("refresh RPC unavailable this cycle - polling with wallet's last known state")

    transfers = rpc_call("get_transfers", {
        "in": True, "pool": True,
        "account_index": account,
        "subaddr_indices": indices,
    }, cfg)

    if transfers is None:
        return
    if not isinstance(transfers, dict):
        log(f"get_transfers returned non-dict: {type(transfers).__name__}", "WARN")
        return
    if len(transfers) > 10:
        log(f"get_transfers too many keys: {len(transfers)}", "WARN")
        return

    try:
        height_res = rpc_call("get_height", {}, cfg)
    except Exception as e:
        log(f"get_height threw: {_sanitize_log_str(str(e), 300)}", "WARN")
        height_res = None
    height = 0
    if isinstance(height_res, dict):
        h = height_res.get("height", 0)
        if isinstance(h, int) and not isinstance(h, bool) and 0 <= h <= 5000000:
            height = h
    if height == 0:
        log("get_height returned 0 - confirmations may be inaccurate this cycle", "WARN")

    in_txs = transfers.get("in")
    pool_txs = transfers.get("pool")
    if in_txs is not None and not isinstance(in_txs, list):
        log("get_transfers in not a list", "WARN")
        in_txs = []
    if pool_txs is not None and not isinstance(pool_txs, list):
        log("get_transfers pool not a list", "WARN")
        pool_txs = []
    txs = (in_txs or []) + (pool_txs or [])
    if len(txs) > 10000:
        log(f"Too many transfers ({len(txs)}) - truncating to 10000", "WARN")
        txs = txs[:10000]
    if not txs:
        debug("No transfers found in this poll")
        return

    debug(f"Found {len(txs)} total transfer(s) across all indices")

    by_index = {}
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        if len(tx) > 50:
            continue
        sub = tx.get("subaddr_index", {})
        if not isinstance(sub, dict):
            continue
        idx = sub.get("minor", -1)
        if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0 or idx > 2000000:
            continue
        if idx not in indices:
            continue
        by_index.setdefault(idx, []).append(tx)

    wallet_id = cfg["wallet_id"]
    if not isinstance(wallet_id, str) or not re.fullmatch(r'[A-Za-z0-9_\-]{1,64}', wallet_id):
        log(f"poll_confirmations bad wallet_id {wallet_id!r}", "ERROR")
        return
    now = server_now(state)
    pushed = 0

    for idx in indices:
        matched = by_index.get(idx, [])
        total = 0.0
        hashes = []
        min_conf = 999999999

        # Merge per txid, keeping the most-confirmed view of each tx. A tx can
        # appear in BOTH the "in" (confirmed) and "pool" lists across refreshes;
        # letting a stale pool twin pin min_conf to 0 froze servers at 0-conf
        # forever even after the wallet showed multiple confirmations.
        best_by_txid = {}
        for tx in matched:
            if not isinstance(tx, dict):
                continue
            amt = tx.get("amount", 0)
            if not isinstance(amt, int) or isinstance(amt, bool) or amt < 0 or amt > 10**18:
                continue
            total += amt / 1e12
            if total > 1e9:
                log(f"Total too large for idx {idx}, capping", "WARN")
                total = 1e9
            txid = tx.get("txid", "")
            tid = txid.lower() if isinstance(txid, str) and re.fullmatch(r'[0-9a-fA-F]{64}', txid) else None
            if tid:
                hashes.append(tid)

            confs = tx.get("confirmations")
            tx_height = tx.get("height")
            is_pool = tx.get("type") == "pool"
            if isinstance(confs, int) and not isinstance(confs, bool) and 0 <= confs <= 10000000:
                c = confs
            elif is_pool or tx_height == 0:
                # monero-wallet-rpc omits "confirmations" for pool transfers and
                # reports height: 0 as its sentinel for "not yet mined" - pin to 0.
                c = 0
            elif isinstance(tx_height, int) and isinstance(height, int) and height and 0 < tx_height <= 5000000:
                c = max(0, height - int(tx_height))
            else:
                c = 0

            prev_c = best_by_txid.get(tid, -1) if tid else None
            if tid:
                if c > prev_c:
                    best_by_txid[tid] = c
                # amount already summed; only confidence tracking is deduped
            elif prev_c is None:
                pass  # unhashable/absent txid: contributes nothing to min_conf below

        # min_conf over the BEST known view of each distinct tx.
        known_confs = [c for c in best_by_txid.values() if c >= 0]
        if not matched:
            known_confs = []
        elif known_confs:
            min_conf = min(known_confs)
        else:
            # No usable txids at all - fall back to 0 rather than infinity.
            min_conf = 0

        # Cap: height-based confirmations grow forever, so a settled payment
        # would otherwise register as "changed" EVERY poll cycle and be
        # re-pushed indefinitely (endless orphan spam for old addresses).
        min_conf = min(min_conf, CONF_CAP)

        if total < 0 or total != total or total in (float('inf'), float('-inf')):
            log(f"Bad total for idx {idx}: {total}", "WARN")
            continue
        if len(hashes) > 100:
            hashes = hashes[:100]

        key = str(idx)
        prev = state["last_seen"].get(key, {})
        if not isinstance(prev, dict):
            prev = {}
        prev_recv = float(prev.get("received", 0.0)) if isinstance(prev.get("received", 0.0), (int, float)) else 0.0
        prev_conf = int(prev.get("confs", 0)) if isinstance(prev.get("confs", 0), int) else 0

        # Heartbeat: indices the SERVER reports as actively reserved/detected
        # are always re-pushed while a transfer is visible. Pure change-
        # detection can go quiet at exactly the wrong time (a missed
        # transition, a pool/in view pinning confs), leaving an open order
        # frozen - periodic re-pushes make the server self-heal instead.
        is_active = idx in state.get("active_watch", [])
        changed = abs(total - prev_recv) >= 1e-12 or min_conf != prev_conf
        if not changed and not (matched and is_active):
            continue

        payload = {
            "v": 1,
            "ts": now,
            "type": "confirmation",
            "wallet_id": wallet_id,
            "subaddress_index": idx,
            "received": round(float(total), 12),
            "confs": int(min_conf),
            "hashes": hashes,
        }
        if len(json.dumps(payload, separators=(',', ':'))) > MAX_DECRYPTED_BYTES:
            log(f"Confirmation payload too large for idx {idx}", "WARN")
            continue

        if wp_push(payload, cfg, box):
            state["last_seen"][key] = {"received": round(float(total), 12), "confs": int(min_conf), "ts": now}
            if len(state["last_seen"]) > MAX_GENERATED_INDICES:
                oldest = sorted(state["last_seen"], key=lambda k: state["last_seen"][k].get("ts", 0))[:len(state["last_seen"]) - MAX_GENERATED_INDICES]
                for k in oldest:
                    state["last_seen"].pop(k, None)
            log(f"Pushed: subaddress {idx} → {total:.12f} XMR, {min_conf} confs, {len(hashes)} tx(s)")
            pushed += 1
        else:
            log(f"Failed to push confirmation for subaddress {idx}", "WARN")

    if pushed > 0:
        save_state(state, cfg)

# ---------------------------------------------------------------------------
# Address supply check (status blob → generate if low) - validated
# ---------------------------------------------------------------------------

def check_address_supply(state, cfg, box):
    if not isinstance(state, dict):
        log("check_address_supply got non-dict state - aborting", "ERROR")
        return
    now = server_now(state)
    try:
        cooldown = int(cfg.get("address_generation_cooldown", 3600))
    except (TypeError, ValueError):
        cooldown = 3600
        log("address_generation_cooldown not an int - using 3600", "WARN")
    cooldown = max(0, min(cooldown, 86400))

    last_push = state.get("last_address_push", 0)
    try:
        last_push = int(last_push)
    except (TypeError, ValueError):
        last_push = 0
    if not (0 <= last_push <= now + 600):
        last_push = 0
    if now - last_push < cooldown:
        debug(f"Address push on cooldown ({cooldown}s), {now - last_push}s elapsed")
        return

    try:
        status = wp_status(cfg, box, ts=now)
    except Exception as e:
        log(f"wp_status threw in check_address_supply: {_sanitize_log_str(str(e), 300)}", "ERROR")
        return
    if not status or not isinstance(status, dict):
        if status is not None:
            log(f"wp_status returned non-dict: {type(status).__name__}", "WARN")
        return
    ok, reason = _validate_status_response(status)
    if not ok:
        log(f"check_address_supply got invalid status: {reason}", "WARN")
        return

    state["last_status_check"] = now

    # Measure server clock skew from the authenticated status response - the
    # ONLY trusted time source this daemon has (the push ack is deliberately
    # indistinguishable between success and silent timestamp rejection).
    # server_now() applies this offset to every outgoing payload ts, so a
    # device clock outside the server's ±300s acceptance window self-corrects
    # here instead of silently losing all confirmation pushes.
    srv_ts = status.get("ts")
    if isinstance(srv_ts, int) and not isinstance(srv_ts, bool):
        measured = max(-600, min(600, srv_ts - int(time.time())))
        prev_off = state.get("server_offset", 0)
        if not isinstance(prev_off, int) or isinstance(prev_off, bool) or not (-600 <= prev_off <= 600):
            prev_off = 0
        if measured != prev_off:
            if abs(measured) > 60:
                log(f"Server clock offset measured at {measured}s (was {prev_off}s) - outgoing timestamps adjusted", "WARN")
            state["server_offset"] = measured
            save_state(state, cfg)

    # Track which subaddress indices hold OPEN orders (reserved/detected).
    # poll_confirmations() heartbeats these so an open order's confirmation
    # stream can never silently stop (see the heartbeat note there).
    aw = status.get("active_indices")
    if isinstance(aw, list):
        clean_aw = sorted({int(v) for v in aw[:MAX_ACTIVE_INDICES]
                           if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2000000})
        if clean_aw != state.get("active_watch"):
            state["active_watch"] = clean_aw

        # ALWAYS adopt server-reported active indices into the watch-list -
        # not just during the empty-state recovery below. A restarted daemon
        # rebuilds its list from its own memory; addresses generated by a
        # PREVIOUS daemon lifetime (or while state was lost) are invisible
        # to get_transfers unless the server tells us they matter. Without
        # this, any checkout served from such an address is paid but NEVER
        # detected - the exact "daemon pushes, server sees nothing" failure.
        gi = set(state.get("generated_indices", []))
        missing = [i for i in clean_aw if i not in gi]
        if missing:
            gi.update(missing)
            state["generated_indices"] = sorted(gi)[:MAX_GENERATED_INDICES]
            save_state(state, cfg)  # persist immediately - survives restarts
            log(f"Watch-list adopted {len(missing)} server-active index(es): "
                f"{sorted(missing)[:10]}{'...' if len(missing) > 10 else ''}", "INFO")

    pool_free = int(status.get("pool_free", 0))
    pool_total = int(status.get("pool_total", 0))
    reserved = int(status.get("reserved_count", 0))
    burn_rate = status.get("burn_rate_24h", 0)
    try:
        burn_rate = float(burn_rate)
    except (TypeError, ValueError):
        burn_rate = 0.0
    if burn_rate != burn_rate or burn_rate in (float('inf'), float('-inf')):
        burn_rate = 0.0
    burn_rate = max(0.0, min(burn_rate, MAX_BURN_RATE))
    resp_net = status.get("network", cfg["network"])
    if resp_net not in ("mainnet", "testnet", "stagenet"):
        resp_net = cfg["network"]

    log(f"Pool ({resp_net}): {pool_free}/{pool_total} free, {reserved} reserved, ~{burn_rate}/h burn rate")

    recovered = status.get("active_indices")
    if not state["generated_indices"] and isinstance(recovered, list) and recovered:
        clean = []
        for v in recovered[:MAX_ACTIVE_INDICES]:
            if isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 2000000:
                clean.append(v)
        if clean:
            clean = sorted(set(clean))[:MAX_ACTIVE_INDICES]
            if len(clean) != len(recovered):
                log(f"State recovery: filtered {len(recovered)} -> {len(clean)} indices", "WARN")
            state["generated_indices"] = clean
            save_state(state, cfg)
            log(f"State recovery: rebuilt watch-list from server ({len(clean)} active indices)")

    if status.get("request_log") is True:
        entries = device_log_entries()
        if len(entries) > 200:
            entries = entries[-200:]
        for e in entries:
            if not isinstance(e, dict) or len(str(e)) > 2048:
                log("Device log entry invalid, dropping", "WARN")
                entries = [x for x in entries if isinstance(x, dict) and len(str(x)) <= 2048][:200]
                break
        payload = {
            "v": 1, "ts": now, "type": "debug_log",
            "wallet_id": cfg["wallet_id"],
            "entries": entries[-150:],
        }
        try:
            sz = len(json.dumps(payload, separators=(',', ':')).encode("utf-8"))
            if sz > MAX_DECRYPTED_BYTES:
                log(f"Device log payload too large ({sz}), truncating", "WARN")
                payload["entries"] = payload["entries"][-50:]
        except Exception:
            pass
        if wp_push(payload, cfg, box):
            log(f"Pushed device debug log ({len(entries)} entries), clearing buffer")
            device_log_clear()
        else:
            log("Failed to push device debug log", "WARN")

    try:
        min_free = int(cfg["min_pool_free"])
    except (TypeError, ValueError):
        min_free = 10
    min_free = max(1, min(min_free, 10000))
    try:
        batch_size = int(cfg["batch_size"])
    except (TypeError, ValueError):
        batch_size = 50
    batch_size = max(1, min(batch_size, 200))

    # Generation is driven ONLY by server-side need: if the server reports
    # enough free addresses, never mint more - not even when our local
    # watch-list is empty. Previously the pool-sufficient early-return also
    # required a non-empty generated_indices, so any fresh/lost state file
    # fell through and created a full batch of subaddresses on EVERY daemon
    # start (indices marching upward, server pool bloated with unused
    # entries). The watch-list itself recovers via status.active_indices
    # adoption above; a genuine fresh install still bootstraps because its
    # server reports pool_free=0 < min_pool_free.
    if pool_free >= min_free:
        debug(f"Pool sufficient ({pool_free} >= {min_free})")
        return

    if not state["generated_indices"]:
        log(f"Watch-list empty and pool low ({pool_free} < {min_free}) - generating initial batch to start watching", "INFO")

    to_generate = max(batch_size, min_free * 2)
    to_generate = max(1, min(to_generate, 200))
    if len(state["generated_indices"]) + to_generate > MAX_GENERATED_INDICES:
        to_generate = MAX_GENERATED_INDICES - len(state["generated_indices"])
        if to_generate <= 0:
            log("Cannot generate: at max indices cap", "WARN")
            return
    log(f"Pool LOW ({pool_free} < {min_free}). Generating {to_generate} addresses on {cfg['network']}...")

    addresses = generate_addresses(to_generate, state, cfg)

    if addresses:
        if len(addresses) > 200:
            log(f"Generated too many addresses ({len(addresses)}), truncating", "WARN")
            addresses = addresses[:200]
        for a in addresses:
            if (not isinstance(a, dict)
                    or not isinstance(a.get("address"), str)
                    or not re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{90,256}', a["address"])
                    or not isinstance(a.get("index"), int)
                    or isinstance(a.get("index"), bool)
                    or not (0 <= a["index"] <= 2000000)):
                log("Generated address entry failed validation, aborting push", "ERROR")
                return
        payload = {
            "v": 1,
            "ts": now,
            "type": "addresses",
            "network": cfg["network"],
            "wallet_id": cfg["wallet_id"],
            "account_index": cfg["account_index"],
            "addresses": addresses,
        }
        try:
            sz = len(json.dumps(payload, separators=(',', ':')).encode("utf-8"))
            if sz > MAX_DECRYPTED_BYTES:
                log(f"Address batch too large ({sz}), aborting", "ERROR")
                return
        except Exception:
            pass
        if wp_push(payload, cfg, box):
            state["last_address_push"] = now
            save_state(state, cfg)
            log(f"Pushed {len(addresses)} addresses ({cfg['network']})")
        else:
            log("Failed to push address batch", "WARN")

# ---------------------------------------------------------------------------
# Prune unused subaddresses + sync removal to server (--prune-addresses)
# ---------------------------------------------------------------------------

PRUNE_CHUNK = 800  # indices per push; ~6KB JSON, well under MAX_DECRYPTED_BYTES

def _chunked_list(seq, n):
    return [seq[i:i + n] for i in range(0, len(seq), max(1, int(n)))]

def _funded_indices(tracked, cfg):
    """Indices among tracked that have ANY incoming transfer record in wallet
    history (confirmed, mempool, or pending). None means the wallet could not
    be read - callers MUST refuse to prune on None."""
    res = rpc_call("get_transfers", {
        "in": True, "pool": True,
        "account_index": cfg["account_index"],
        "subaddr_indices": tracked,
    }, cfg)
    if res is None:
        return None
    if not isinstance(res, dict):
        log(f"get_transfers returned non-dict: {type(res).__name__}", "ERROR")
        return None
    funded = set()
    for group in ("in", "pool", "pending"):
        entries = res.get(group)
        if not isinstance(entries, list):
            continue
        for t in entries:
            if isinstance(t, dict):
                try:
                    idx = int(t.get("subaddr_index", -1))
                except (TypeError, ValueError):
                    continue
                if 0 <= idx <= 2000000:
                    funded.add(idx)
    return funded

def cmd_prune_addresses(cfg, state, keep=None, dry_run=False):
    """One-shot cleanup: stop watching never-funded subaddresses that hold no
    open order, and ask every configured server to drop them from its pushed
    address pool. The wallet FILE keeps them - monero-wallet-rpc cannot delete
    subaddresses; pruning only affects what this daemon watches and what the
    server serves to new checkouts."""
    if not isinstance(state, dict) or not isinstance(state.get("generated_indices"), list):
        log("Invalid state - aborting prune", "ERROR")
        return 1
    tracked = sorted({int(x) for x in state["generated_indices"]
                      if isinstance(x, int) and not isinstance(x, bool) and 0 <= x <= 2000000})
    if not tracked:
        log("No subaddress indices tracked - nothing to prune")
        return 0

    if keep is None:
        try:
            keep = int(cfg.get("min_pool_free", 10))
        except (TypeError, ValueError):
            keep = 10
    keep = max(0, min(int(keep), 10000))

    funded = _funded_indices(tracked, cfg)
    if funded is None:
        log("Could not read wallet transfer history - refusing to prune "
            "(cannot determine which addresses are unused)", "ERROR")
        return 1

    servers = _get_server_list(cfg)
    if not servers:
        log("No usable server configuration - aborting prune", "ERROR")
        return 1

    plans = []
    protected_union = set()
    for srv in servers:
        per = dict(cfg)
        per["wp_url"] = srv["wp_url"]
        per["wp_post_field"] = srv["wp_post_field"]
        per["wp_status_param"] = srv["wp_status_param"]
        per["shared_secret_hex"] = srv["shared_secret_hex"]
        box = crypto_init(per)
        if box is None:
            log(f"[{srv['label']}] no usable shared secret - aborting prune", "ERROR")
            return 1
        per["_signing_key"] = cfg.get("_signing_key")

        status = None
        try:
            status = wp_status(per, box, ts=server_now(state))
        except Exception as e:
            log(f"[{srv['label']}] wp_status threw: {_sanitize_log_str(str(e), 300)}", "ERROR")
        if not isinstance(status, dict):
            log(f"[{srv['label']}] status unavailable - refusing to prune", "ERROR")
            return 1
        ok, reason = _validate_status_response(status)
        if not ok:
            log(f"[{srv['label']}] invalid status ({reason}) - refusing to prune", "ERROR")
            return 1

        aw = status.get("active_indices") or []
        active = {int(v) for v in aw if isinstance(v, int) and not isinstance(v, bool)}
        protected_union |= active

        # Never touch funded addresses or indices holding open orders.
        candidates = sorted(set(tracked) - active - funded)

        # Keep the lowest-index unused addresses (default min_pool_free worth)
        # so pool_free stays above the refill floor and pruning does not
        # trigger a fresh generation burst right after it.
        to_prune = candidates[keep:] if len(candidates) > keep else []
        plans.append((srv["label"], per, box, candidates, to_prune))

    funded_tracked = len(set(tracked) & funded)
    log(f"Prune plan: tracking {len(tracked)}, funded {funded_tracked}, "
        f"active(open orders) {len(protected_union & set(tracked))}, keep {keep} unused")

    for label, _, _, cands, prune_list in plans:
        preview = f" - e.g. {prune_list[:20]}{'...' if len(prune_list) > 20 else ''}" if prune_list else ""
        log(f"[{label}] unused {len(cands)}, would prune {len(prune_list)}{preview}")

    if dry_run:
        log("Dry run only - nothing pushed, watch-list untouched")
        return 0

    # Push prune requests chunk-by-chunk. Every server must succeed before
    # the local watch-list is touched; pushes are idempotent, so a failed run
    # can simply be repeated after connectivity is fixed.
    all_ok = True
    now_ts = server_now(state)
    for label, per, box, _, prune_list in plans:
        pushed = 0
        for chunk in _chunked_list(prune_list, PRUNE_CHUNK):
            payload = {
                "v": 1,
                "ts": now_ts,
                "type": "prune_addresses",
                "network": per["network"],
                "wallet_id": per["wallet_id"],
                "account_index": per["account_index"],
                "indices": chunk,
            }
            try:
                sz = len(json.dumps(payload, separators=(',', ':')).encode("utf-8"))
            except Exception:
                sz = MAX_DECRYPTED_BYTES + 1
            if sz > MAX_DECRYPTED_BYTES:
                log(f"[{label}] prune payload too large ({sz}B) - aborting this server", "ERROR")
                all_ok = False
                break
            if wp_push(payload, per, box):
                pushed += len(chunk)
            else:
                log(f"[{label}] prune push failed after {pushed}/{len(prune_list)} indices", "WARN")
                all_ok = False
                break
        if all_ok:
            log(f"[{label}] server asked to prune {pushed} address(es)")

    if not all_ok:
        log("Prune incomplete - local watch-list NOT modified. Fix connectivity and re-run.", "WARN")
        return 1

    # Local cleanup: only indices pruned on EVERY server (intersection), minus
    # anything protected anywhere. Multi-server runs with differing candidate
    # sets stay consistent by construction.
    removal = None
    for _, _, _, _, prune_list in plans:
        s = set(prune_list)
        removal = s if removal is None else (removal & s)
    removal = (removal or set()) - protected_union - funded
    if removal:
        state["generated_indices"] = sorted(set(tracked) - removal)[:MAX_GENERATED_INDICES]
        save_state(state, cfg)
    log(f"Prune complete: removed {len(removal)} from local watch-list "
        f"({len(state['generated_indices'])} remain tracked)")
    return 0

# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def shutdown(signum=None, frame=None):
    global RUNNING
    log("Received signal, shutting down...")
    _restore_console_mode()
    RUNNING = False


def _in_modern_terminal():
    """True in Windows Terminal / VS Code - they handle mouse selection
    themselves, so disabling QuickEdit would only break copy/paste."""
    return bool(os.environ.get("WT_SESSION") or os.environ.get("TERM_PROGRAM"))


def _disable_quickedit():
    """Classic conhost only: clear ENABLE_QUICK_EDIT_MODE (0x0040) and
    ENABLE_INSERT_MODE (0x0020) so clicking the window doesn't freeze the
    daemon's output (xmr.txt C3). Skipped in Windows Terminal / VS Code and
    when --no-console-fix is given; the previous mode is restored on exit so
    mouse copy/paste works again after the daemon stops."""
    global _ORIG_CONSOLE_MODE
    if os.name != "nt" or NO_CONSOLE_FIX or _in_modern_terminal():
        return
    try:
        import ctypes
        _k32 = ctypes.windll.kernel32
        _h = _k32.GetStdHandle(-10)  # STD_INPUT_HANDLE
        _mode = ctypes.c_uint32()
        if _k32.GetConsoleMode(_h, ctypes.byref(_mode)):
            _ORIG_CONSOLE_MODE = _mode.value
            _k32.SetConsoleMode(_h, _mode.value & ~0x0060)
            log("Console QuickEdit disabled so clicking won't freeze output. "
                "To copy console output: run with --log-file=PATH, or add "
                "--no-console-fix to keep classic mouse selection.", "INFO")
    except Exception:
        pass


def _restore_console_mode():
    global _ORIG_CONSOLE_MODE
    if _ORIG_CONSOLE_MODE is None:
        return
    try:
        import ctypes
        _k32 = ctypes.windll.kernel32
        _h = _k32.GetStdHandle(-10)
        _k32.SetConsoleMode(_h, _ORIG_CONSOLE_MODE)
    except Exception:
        pass
    _ORIG_CONSOLE_MODE = None

# ---------------------------------------------------------------------------
# Interactive config editor (--edit flag)
# ---------------------------------------------------------------------------

EDIT_FIELDS = [
    ("a", "wp_url",                  "str",  "WordPress site URL"),
    ("b", "wp_post_field",           "str",  "POST field name (disguise)"),
    ("c", "wp_status_param",         "str",  "Status query param (disguise)"),
    ("d", "shared_secret_hex",       "hex64","Shared secret (64 hex chars)"),
    ("e", "wallet_rpc_url",          "str",  "Wallet-RPC URL"),
    ("f", "wallet_rpc_user",         "str",  "Wallet-RPC username"),
    ("g", "wallet_rpc_pass",         "str",  "Wallet-RPC password"),
    ("h", "wallet_id",               "str",  "Wallet ID (match WP config)"),
    ("i", "account_index",           "int",  "Wallet account index"),
    ("j", "network",                 "net",  "Network (mainnet/testnet/stagenet)"),
    ("k", "poll_interval",           "int",  "Poll interval (seconds)"),
    ("l", "status_interval",         "int",  "Status check interval (seconds)"),
    ("m", "min_pool_free",           "int",  "Min free addresses before refill"),
    ("n", "batch_size",              "int",  "Addresses to generate per batch"),
    ("o", "address_generation_cooldown","int","Cooldown between address pushes (s)"),
    ("p", "debug",                   "bool", "Debug logging (true/false)"),
    ("q", "tls_verify",              "bool", "Verify TLS certificates (true/false)"),
]

def _display_config(cfg):
    print()
    print("\033[1mCurrent configuration:\033[0m")
    print("─" * 56)
    for key, ck, kind, desc in EDIT_FIELDS:
        val = cfg.get(ck, DEFAULTS.get(ck, ""))
        if ck in ("shared_secret_hex", "wallet_rpc_pass") and val and len(str(val)) > 12:
            display_val = str(val)[:8] + "..." + str(val)[-4:]
        elif isinstance(val, bool):
            display_val = "true" if val else "false"
        else:
            display_val = _sanitize_log_str(str(val) if val != "" else "\033[2m(not set)\033[0m", 80)
        print(f"  \033[1m{key}\033[0m  {desc:<34} \033[36m{display_val}\033[0m")
    print("─" * 56)

def _validate_field(ck, kind, raw):
    raw = raw.strip()
    if len(raw) > 2048:
        return None
    if kind == "str":
        if "\x00" in raw or "\n" in raw or "\r" in raw:
            return None
        return raw
    if kind == "int":
        if not raw.lstrip("-").isdigit():
            return None
        try:
            v = int(raw)
        except ValueError:
            return None
        if not (-1000000 <= v <= 1000000):
            return None
        if v < 0 and ck not in ("account_index",):
            if v < 0:
                return None
        return v
    if kind == "bool":
        low = raw.lower()
        if low in ("true", "1", "yes", "y", "on"):
            return True
        if low in ("false", "0", "no", "n", "off"):
            return False
        return None
    if kind == "hex64":
        clean = raw.replace(" ", "").lower()
        if len(clean) != 64:
            return None
        if not re.fullmatch(r'[0-9a-f]{64}', clean):
            return None
        try:
            bytes.fromhex(clean)
            return clean
        except ValueError:
            return None
    if kind == "net":
        low = raw.lower()
        if low in ("mainnet", "testnet", "stagenet"):
            return low
        return None
    return raw

def interactive_edit(config_path=None):
    if config_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(script_dir, "xmr-pushd.conf")

    cfg = {}
    if os.path.exists(config_path):
        if os.path.getsize(config_path) > 65536:
            print(f"\033[31mConfig too large, starting fresh.\033[0m")
            cfg = {}
        else:
            try:
                with open(config_path, "r") as f:
                    cfg = json.load(f)
                if not isinstance(cfg, dict):
                    raise ValueError("not an object")
                print(f"\nLoaded config from: {config_path}")
            except (json.JSONDecodeError, IOError, ValueError) as e:
                print(f"\n\033[33mWarning: Could not parse {config_path} ({_sanitize_log_str(str(e), 200)}), starting from defaults.\033[0m")
                cfg = {}

    for k, v in DEFAULTS.items():
        cfg.setdefault(k, v)

    while True:
        _display_config(cfg)
        choice = input("\nEnter key to edit (\033[1m?\033[0m=help, \033[1mw\033[0m=write, \033[1mq\033[0m=quit): ").strip().lower()
        if len(choice) > 4:
            print("\033[33mInput too long\033[0m")
            continue

        if choice == "q":
            print("Exited without saving.")
            return
        if choice == "w":
            errs = validate_config(cfg)
            if errs:
                print("\033[31mConfig validation failed:\033[0m")
                for e in errs:
                    print(f"  - {e}")
                print("Fix errors before saving.")
                continue
            tmp = config_path + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump(cfg, f, indent=2)
                os.chmod(tmp, 0o600)
                os.replace(tmp, config_path)
                os.chmod(config_path, 0o600)
            except Exception as e:
                print(f"\033[31mFailed to write config: {e}\033[0m")
                try:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                except Exception:
                    pass
                continue
            print(f"\033[32m[ok] Config written to {config_path} (0600)\033[0m")
            return
        if choice == "?":
            print("\n  Keys  a-q  edit a field")
            print("  Enter blank to keep the current value")
            print("  w         write config and exit (validated)")
            print("  q         quit without saving")
            input("\nPress Enter to continue...")
            continue

        field = None
        for key, ck, kind, desc in EDIT_FIELDS:
            if choice == key:
                field = (ck, kind, desc)
                break

        if field is None:
            print(f"\033[33mUnknown key: {_sanitize_log_str(choice, 16)}\033[0m")
            continue

        ck, kind, desc = field
        current = cfg.get(ck, DEFAULTS.get(ck, ""))
        display = str(current)
        if ck in ("shared_secret_hex", "wallet_rpc_pass") and current and len(str(current)) > 12:
            display = str(current)[:8] + "..." + str(current)[-4:]
        elif isinstance(current, bool):
            display = "true" if current else "false"

        print(f"\n  {desc}  [\033[2m{_sanitize_log_str(display, 80)}\033[0m]")
        raw = input(f"  New value (Enter = keep): ")
        if len(raw) > 2048:
            print("  \033[31m[x] Input too long\033[0m")
            continue

        if raw.strip() == "":
            print("  \033[2m(unchanged)\033[0m")
            continue

        parsed = _validate_field(ck, kind, raw)
        if parsed is None:
            print(f"  \033[31m[x] Invalid value for {kind}\033[0m")
            continue

        prev_network = cfg.get("network", "mainnet")
        cfg[ck] = parsed
        if ck == "network" and parsed != prev_network:
            if _auto_correct_wallet_port(cfg, old_network=prev_network):
                print(f"  \033[36mwallet_rpc_url auto-adjusted to {cfg['wallet_rpc_url']} for {parsed}\033[0m")
        print(f"  \033[32m[ok] Updated\033[0m")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global RUNNING, DEBUG, LOG_FILE, NO_CONSOLE_FIX

    config_path = None
    edit_mode = False
    pair_mode_args = None
    prune_mode = False
    prune_dry = False
    prune_keep = None
    for arg in sys.argv[1:]:
        if len(arg) > 512:
            die(f"Argument too long: {arg[:40]}...")
        if arg == "--debug":
            DEBUG = True
        elif arg == "--edit":
            edit_mode = True
        elif arg == "--pair":
            pair_mode_args = []
        elif arg == "--prune-addresses":
            prune_mode = True
        elif arg == "--prune-dry-run":
            prune_dry = True
        elif arg.startswith("--prune-keep="):
            pv = arg[len("--prune-keep="):].strip()
            try:
                prune_keep = int(pv)
            except ValueError:
                die("--prune-keep requires an integer (0..10000)")
            if not (0 <= prune_keep <= 10000):
                die("--prune-keep must be 0..10000")
        elif arg == "--no-console-fix":
            NO_CONSOLE_FIX = True
        elif arg.startswith("--log-file="):
            lp = arg[len("--log-file="):].strip()
            if not lp or len(lp) > 512 or "\x00" in lp:
                die("--log-file requires a valid path")
            LOG_FILE = lp
        elif arg.startswith("-"):
            die(f"Unknown flag: {_sanitize_log_str(arg, 64)}")
        elif not arg.startswith("-"):
            if pair_mode_args is not None:
                pair_mode_args.append(arg)
            elif config_path is not None:
                die("Only one config path allowed")
            else:
                config_path = arg

    if "--show-pubkey" in sys.argv[1:]:
        tmp_cfg = {}
        try:
            if config_path and os.path.exists(config_path):
                with open(config_path, "r") as f:
                    tmp_cfg = json.load(f)
            elif os.path.exists(_config_path_default()):
                with open(_config_path_default(), "r") as f:
                    tmp_cfg = json.load(f)
        except Exception:
            pass
        pk = (tmp_cfg.get("signing_pubkey_hex") or "").strip()
        if pk and len(pk) == 64:
            print(pk.lower())
            sys.exit(0)
        print("No signing key yet - run without flags once or use --edit to generate.", file=sys.stderr)
        sys.exit(1)

    if edit_mode:
        interactive_edit(config_path)
        sys.exit(0)

    if pair_mode_args is not None:
        if len(pair_mode_args) not in (2, 3):
            die("Usage: python3 xmr-pushd.py --pair <word1> <word2> [<word3>]")
        if len(pair_mode_args) == 3:
            pair_mode(pair_mode_args[0], pair_mode_args[1], pair_mode_args[2], config_path)
        else:
            pair_mode(pair_mode_args[0], pair_mode_args[1], None, config_path)
        sys.exit(0)

    if not HAS_NACL:
        die("pynacl is not installed.\n"
            "Run: apt install python3-pip && pip install pynacl")

    cfg = load_config(config_path)

    if cfg.get("debug"):
        DEBUG = True

    has_servers = isinstance(cfg.get("servers"), list) and len(cfg["servers"]) > 0
    if has_servers:
        servers_preview = _get_server_list(cfg)
        if not servers_preview:
            die("servers is set but produced no valid server entries - fix xmr-pushd.conf")
    else:
        if not cfg["wp_url"]:
            die("wp_url is not set in config. Set this to your WordPress site URL (e.g. http://192.168.1.100 for LAN testing).")
        if not cfg["shared_secret_hex"] or cfg["shared_secret_hex"] == DEFAULTS["shared_secret_hex"]:
            die("shared_secret_hex is not set in config. Copy the 64-char hex key from WordPress → Settings → Monero Push.")

    network = cfg.get("network", "mainnet")
    if network not in ("mainnet", "testnet", "stagenet"):
        die(f"network must be 'mainnet', 'testnet', or 'stagenet' (got '{_sanitize_log_str(network, 32)}').")

    try:
        signing_key = _ensure_signing_keys(cfg, config_path or _config_path_default())
        cfg["_signing_key"] = signing_key
        if signing_key is not None:
            pub = cfg.get("signing_pubkey_hex", "")[:16]
            log(f"Ed25519 signing enabled - pubkey {pub}...", "INFO")
        else:
            log("No signing key - pushes will be unsigned (legacy). Pair with WordPress to enable signatures.", "WARN")
    except Exception as e:
        log(f"signing setup failed: {e}", "WARN")
        signing_key = None
        cfg["_signing_key"] = None

    box = crypto_init(cfg)
    if box is None and not has_servers:
        die("No usable shared secret and no servers[]. Configure shared_secret_hex or servers[].")
    state = load_state(cfg)

    # One-shot prune mode: clean unused subaddresses locally + on the server,
    # then exit. Runs AFTER signing keys are set up so pushes are signed.
    if prune_mode:
        sys.exit(cmd_prune_addresses(cfg, state, keep=prune_keep, dry_run=prune_dry))

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # Classic-conhost only: disable QuickEdit so clicking the window doesn't
    # freeze the output (xmr.txt C3). Skipped in Windows Terminal / VS Code
    # and with --no-console-fix; the previous mode is restored on exit so
    # mouse copy/paste returns afterward. All console output is also mirrored
    # to --log-file=PATH, giving you a file you can open/copy instead of
    # selecting text in the freeze-safe console.
    _disable_quickedit()
    atexit.register(_restore_console_mode)
    if LOG_FILE:
        print(f"Console output will be mirrored to: {LOG_FILE}", flush=True)

    version = rpc_call("get_version", {}, cfg)
    if version and isinstance(version, dict):
        log(f"Connected to wallet-rpc v{_sanitize_log_str(str(version.get('version', '?')), 32)} on {cfg['network']}")
    else:
        log("WARNING: Could not reach wallet-rpc at " + _sanitize_log_str(cfg["wallet_rpc_url"], 120), "WARN")
        log("Daemon will keep retrying. Check: is wallet-rpc running? Is the URL/port correct?", "WARN")

    if has_servers:
        for srv in _get_server_list(cfg):
            log(f"Server [{srv['label']}]: {_sanitize_log_str(srv['wp_url'], 100)}", "INFO")
    else:
        log(f"WordPress: {_sanitize_log_str(cfg['wp_url'], 120)}  |  Network: {cfg['network']}")
    log(f"Wallet ID: {_sanitize_log_str(cfg['wallet_id'], 64)}  |  Account: {cfg['account_index']}")
    log(f"Poll: every {cfg['poll_interval']}s  |  Status check: every {cfg['status_interval']}s")
    log(f"Pool floor: {cfg['min_pool_free']}  |  Batch size: {cfg['batch_size']}")
    log(f"TLS verify: {cfg.get('tls_verify', True)}  |  Debug: {DEBUG}")
    log(f"Tracking {len(state['generated_indices'])} previously-generated subaddresses")
    log(f"State file: {_resolve_state_path(cfg)}")
    if LOG_FILE:
        log(f"Console output mirrored to: {LOG_FILE}")
    log("Daemon running. Press Ctrl+C to stop.")

    # One-time initial status check: bootstraps the watch-list from the
    # server (fresh installs start with no generated_indices) and starts the
    # status-interval clock, so the daemon doesn't wait up to status_interval
    # before first contact (xmr.txt "doesnt track previously generated
    # addresses correctly").
    try:
        if has_servers:
            for srv in _get_server_list(cfg):
                per = dict(cfg)
                per["wp_url"] = srv["wp_url"]
                per["wp_post_field"] = srv["wp_post_field"]
                per["wp_status_param"] = srv["wp_status_param"]
                per["shared_secret_hex"] = srv["shared_secret_hex"]
                per_box = crypto_init(per)
                if per_box is None:
                    continue
                per["_signing_key"] = cfg.get("_signing_key")
                check_address_supply(state, per, per_box)
        else:
            check_address_supply(state, cfg, box)
    except Exception:
        log(f"Initial status check failed (daemon will retry on schedule):\n{_sanitize_log_str(traceback.format_exc(), 2000)}", "WARN")

    last_save = time.time()
    consecutive_poll_fail = 0

    def _fan_out(callable_name, *a, **kw):
        if has_servers:
            results = []
            for srv in _get_server_list(cfg):
                per = dict(cfg)
                per["wp_url"] = srv["wp_url"]
                per["wp_post_field"] = srv["wp_post_field"]
                per["wp_status_param"] = srv["wp_status_param"]
                per["shared_secret_hex"] = srv["shared_secret_hex"]
                per_box = crypto_init(per)
                if per_box is None:
                    log(f"[{srv['label']}] no usable secret - skipping", "WARN")
                    continue
                per["_signing_key"] = cfg.get("_signing_key")
                fn = globals()[callable_name]
                try:
                    results.append(fn(*a[:1], per, per_box, *a[2:], **kw) if callable_name == "poll_confirmations" else fn(*a, **{**kw, "cfg": per, "box": per_box}) if callable_name == "check_address_supply" else fn(*a, **kw))
                except Exception:
                    log(f"[{srv['label']}] {callable_name} crashed:\n{_sanitize_log_str(traceback.format_exc(), 2000)}", "ERROR")
            return results
        return None

    while RUNNING:
        cycle_start = time.time()
        now_cycle = int(time.time())

        # xmr.txt: "poll" = LOCAL wallet-rpc only, every poll_interval.
        # "status" = the ONLY thing that talks to the server, every status_interval.
        # New incoming transfers are pushed immediately by poll_confirmations.
        try:
            status_interval = int(cfg.get("status_interval", 43200))
        except (TypeError, ValueError):
            status_interval = 43200
        status_interval = max(60, min(status_interval, 604800))
        last_status_ts = state.get("last_status_check", 0)
        try:
            last_status_ts = int(last_status_ts)
        except (TypeError, ValueError):
            last_status_ts = 0
        status_due = now_cycle - last_status_ts >= status_interval

        if has_servers:
            try:
                for srv in _get_server_list(cfg):
                    per = dict(cfg)
                    per["wp_url"] = srv["wp_url"]
                    per["wp_post_field"] = srv["wp_post_field"]
                    per["wp_status_param"] = srv["wp_status_param"]
                    per["shared_secret_hex"] = srv["shared_secret_hex"]
                    per_box = crypto_init(per)
                    if per_box is None:
                        continue
                    per["_signing_key"] = cfg.get("_signing_key")
                    poll_confirmations(state, per, per_box)
                consecutive_poll_fail = 0
            except Exception:
                consecutive_poll_fail += 1
                log(f"Confirmation poll crashed ({consecutive_poll_fail} in a row):\n{_sanitize_log_str(traceback.format_exc(), 2000)}", "ERROR")
                if consecutive_poll_fail >= 5:
                    log("Too many poll crashes - sleeping 60s", "ERROR")
                    for _ in range(60):
                        if not RUNNING:
                            break
                        time.sleep(1)
                    consecutive_poll_fail = 0
        else:
            try:
                poll_confirmations(state, cfg, box)
                consecutive_poll_fail = 0
            except Exception:
                consecutive_poll_fail += 1
                log(f"Confirmation poll crashed ({consecutive_poll_fail} in a row):\n{_sanitize_log_str(traceback.format_exc(), 2000)}", "ERROR")
                if consecutive_poll_fail >= 5:
                    log("Too many poll crashes - sleeping 60s", "ERROR")
                    for _ in range(60):
                        if not RUNNING:
                            break
                        time.sleep(1)
                    consecutive_poll_fail = 0

        if status_due:
            if has_servers:
                for srv in _get_server_list(cfg):
                    per = dict(cfg)
                    per["wp_url"] = srv["wp_url"]
                    per["wp_post_field"] = srv["wp_post_field"]
                    per["wp_status_param"] = srv["wp_status_param"]
                    per["shared_secret_hex"] = srv["shared_secret_hex"]
                    per_box = crypto_init(per)
                    if per_box is None:
                        continue
                    per["_signing_key"] = cfg.get("_signing_key")
                    try:
                        check_address_supply(state, per, per_box)
                    except Exception:
                        log(f"[{srv['label']}] Address supply check crashed:\n{_sanitize_log_str(traceback.format_exc(), 2000)}", "ERROR")
            else:
                try:
                    check_address_supply(state, cfg, box)
                except Exception:
                    log(f"Address supply check crashed:\n{_sanitize_log_str(traceback.format_exc(), 2000)}", "ERROR")
        else:
            debug(f"Status check not due ({now_cycle - last_status_ts}s < {status_interval}s) - server not pinged")

        if time.time() - last_save > 300:
            save_state(state, cfg)
            last_save = time.time()

        if _consecutive_invalid >= CONSECUTIVE_INVALID_THRESHOLD:
            sleep_for = 60
            log(f"Backing off {sleep_for}s due to repeated invalid server responses", "WARN")
        else:
            elapsed = time.time() - cycle_start
            sleep_for = max(1, cfg["poll_interval"] - elapsed)
        waited = 0
        while RUNNING and waited < sleep_for:
            time.sleep(1)
            waited += 1

    save_state(state, cfg)
    log("xmr-pushd stopped.")

# ---------------------------------------------------------------------------
# Insecure word-based pairing (--pair mode)
# ---------------------------------------------------------------------------

# 2048-word list for SAS display (BIP39-compatible, sorted alphabetically)
SAS_WORDLIST = [
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "africa", "after", "again",
    "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle",
    "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow",
    "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur",
    "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger",
    "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer",
    "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple",
    "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm",
    "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow",
    "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset",
    "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude",
    "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn",
    "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful",
    "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance",
    "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain",
    "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty",
    "because", "become", "beef", "before", "begin", "behave", "behind", "believe",
    "below", "belt", "bench", "benefit", "best", "betray", "better", "between",
    "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth",
    "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless",
    "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board",
    "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost",
    "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy",
    "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick",
    "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze",
    "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo",
    "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger",
    "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage",
    "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera",
    "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas",
    "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo",
    "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual",
    "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution",
    "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain",
    "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase",
    "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken",
    "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk",
    "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim",
    "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click",
    "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close",
    "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach",
    "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color",
    "column", "combine", "come", "comfort", "comic", "common", "company", "concert",
    "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook",
    "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost",
    "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote",
    "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl",
    "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp",
    "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise",
    "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup",
    "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute",
    "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash",
    "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december",
    "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy",
    "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny",
    "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert",
    "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device",
    "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet",
    "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt",
    "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance",
    "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll",
    "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double",
    "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress",
    "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry",
    "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf",
    "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east",
    "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort",
    "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element",
    "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge",
    "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless",
    "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy",
    "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry",
    "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion",
    "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics",
    "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange",
    "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile",
    "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose",
    "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty",
    "fade", "faint", "faith", "fall", "false", "fame", "family", "famous",
    "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father",
    "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed",
    "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber",
    "fiction", "field", "figure", "file", "film", "filter", "final", "find",
    "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish",
    "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor",
    "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid",
    "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow",
    "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum",
    "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent",
    "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen",
    "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget",
    "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden",
    "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze",
    "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant",
    "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance",
    "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove",
    "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla",
    "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant",
    "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit",
    "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt",
    "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster",
    "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have",
    "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height",
    "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill",
    "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole",
    "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror",
    "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge",
    "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry",
    "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle",
    "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune",
    "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase",
    "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale",
    "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input",
    "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest",
    "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue",
    "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans",
    "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge",
    "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen",
    "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom",
    "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife",
    "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake",
    "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry",
    "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf",
    "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure",
    "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level",
    "liar", "liberty", "library", "license", "life", "lift", "light", "like",
    "limb", "limit", "link", "lion", "liquid", "list", "little", "live",
    "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely",
    "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky",
    "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad",
    "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal",
    "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble",
    "march", "margin", "marine", "market", "marriage", "mask", "mass", "master",
    "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow",
    "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt",
    "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry",
    "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million",
    "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery",
    "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify",
    "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral",
    "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse",
    "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum",
    "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive",
    "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck",
    "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net",
    "network", "neutral", "never", "news", "next", "nice", "night", "noble",
    "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note",
    "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut",
    "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious",
    "occur", "ocean", "october", "odor", "off", "offer", "office", "often",
    "oil", "okay", "old", "olive", "olympic", "omit", "once", "one",
    "onion", "online", "only", "open", "opera", "opinion", "oppose", "option",
    "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original",
    "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval",
    "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact",
    "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic",
    "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass",
    "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment",
    "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil",
    "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo",
    "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon",
    "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza",
    "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck",
    "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police",
    "pond", "pony", "pool", "popular", "portion", "position", "possible", "post",
    "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict",
    "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary",
    "print", "priority", "prison", "private", "prize", "problem", "process", "produce",
    "profit", "program", "project", "promote", "proof", "property", "prosper", "protect",
    "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin",
    "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push",
    "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick",
    "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar",
    "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random",
    "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor",
    "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe",
    "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret",
    "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember",
    "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat",
    "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response",
    "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward",
    "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle",
    "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival",
    "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof",
    "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal",
    "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad",
    "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt",
    "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage",
    "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme",
    "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script",
    "scrub", "sea", "search", "season", "seat", "second", "secret", "section",
    "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior",
    "sense", "sentence", "series", "service", "session", "settle", "setup", "seven",
    "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield",
    "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop",
    "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling",
    "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly",
    "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate",
    "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt",
    "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight",
    "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile",
    "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap",
    "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid",
    "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul",
    "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn",
    "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider",
    "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport",
    "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel",
    "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start",
    "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick",
    "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove",
    "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble",
    "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer",
    "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super",
    "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey",
    "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet",
    "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup",
    "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank",
    "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team",
    "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text",
    "thank", "that", "theme", "then", "theory", "there", "they", "thing",
    "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket",
    "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired",
    "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together",
    "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool",
    "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss",
    "total", "tourist", "toward", "tower", "town", "toy", "track", "trade",
    "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray",
    "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim",
    "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust",
    "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey",
    "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two",
    "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover",
    "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit",
    "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade",
    "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use",
    "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague",
    "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast",
    "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify",
    "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory",
    "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa",
    "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano",
    "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall",
    "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste",
    "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather",
    "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale",
    "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide",
    "width", "wife", "wild", "will", "win", "window", "wine", "wing",
    "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness",
    "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world",
    "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong",
    "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero",
    "zone", "zoo"
]

def _words_to_bits(word1, word2, word3=None):
    """Convert 2 or 3 words to a bit integer using the SAS wordlist.
    
    With 2 words: 22 bits (legacy, deprecated).
    With 3 words: 33 bits (current).
    """
    try:
        i1 = SAS_WORDLIST.index(word1.lower().strip())
        i2 = SAS_WORDLIST.index(word2.lower().strip())
        if word3 is not None:
            i3 = SAS_WORDLIST.index(word3.lower().strip())
            return (i1 << 22) | (i2 << 11) | i3
        return (i1 << 11) | i2
    except ValueError:
        return None

def _bits_to_words(bits):
    """Convert a bit integer to 2 or 3 words from the SAS wordlist.
    
    If bits fits in 22 bits (≤ 0x3FFFFF), returns 2 words (legacy).
    If bits requires 33 bits (> 0x3FFFFF), returns 3 words.
    """
    if bits > 0x3FFFFF:
        # 33 bits → 3 words
        i1 = (bits >> 22) & 0x7FF
        i2 = (bits >> 11) & 0x7FF
        i3 = bits & 0x7FF
        if i1 >= len(SAS_WORDLIST) or i2 >= len(SAS_WORDLIST) or i3 >= len(SAS_WORDLIST):
            return ["????", "????", "????"]
        return [SAS_WORDLIST[i1], SAS_WORDLIST[i2], SAS_WORDLIST[i3]]
    else:
        # 22 bits → 2 words (legacy)
        i1 = (bits >> 11) & 0x7FF
        i2 = bits & 0x7FF
        if i1 >= len(SAS_WORDLIST) or i2 >= len(SAS_WORDLIST):
            return ["????", "????"]
        return [SAS_WORDLIST[i1], SAS_WORDLIST[i2]]

def _pairing_keys(rx_key, tx_key, pairing_id, encrypted_dev_pk_b64):
    """Derive SAS words AND the paired shared secret, mirroring the PHP server.

    PHP (class-wc-xmr-push-pairing.php, xmr.txt #2/#8/#9):
      k1, k2     = sorted(rx_key, tx_key)
      sas_hash   = generichash(k1 || k2 || pairing_id || encrypted_dev_pk || "xmr-push-pairing-v1", 32)
      paired_sec = generichash(k1 || k2 || pairing_id || encrypted_dev_pk || "xmr-push-paired-secret-v1", 32)

    Binding the RAW encrypted device pk (wire key still 'encrypted_phone_pk', the exact base64url string POSTed to the
    server) into both hashes is what makes the human SAS check confirm THIS
    device's authorized key, and makes the paired secret identical on both sides.
    """
    from nacl.hash import generichash
    # Sort keys for canonical ordering (both sides agree on SAS)
    k1, k2 = (rx_key, tx_key) if rx_key < tx_key else (tx_key, rx_key)
    pairing_bytes = pairing_id.encode("ascii")
    ciphertext_bytes = encrypted_dev_pk_b64.encode("ascii")

    sas_hash = generichash(
        k1 + k2 + pairing_bytes + ciphertext_bytes + b"xmr-push-pairing-v1",
        digest_size=32,
        encoder=RawEncoder,
    )
    # Use first 33 bits of SAS hash for 3 BIP39 words (matching PHP).
    val = ((sas_hash[0] << 32) | (sas_hash[1] << 24) | (sas_hash[2] << 16) | (sas_hash[3] << 8) | sas_hash[4]) & 0x1FFFFFFFF
    sas_words = _bits_to_words(val)

    paired_secret = generichash(
        k1 + k2 + pairing_bytes + ciphertext_bytes + b"xmr-push-paired-secret-v1",
        digest_size=32,
        encoder=RawEncoder,
    )
    return sas_words, paired_secret


def _sas_words_from_shared_secret(rx_key, tx_key, pairing_id, encrypted_dev_pk_b64=""):
    """Backward-compat wrapper: SAS words only (used before ciphertext is available)."""
    words, _ = _pairing_keys(rx_key, tx_key, pairing_id, encrypted_dev_pk_b64)
    return words

def _json_loads_or_die(body_text, content_type, http_status, what, snippet_limit=500):
    """Parse body_text as JSON, or die with a targeted error describing what
    the server actually returned (HTML page, wrong Content-Type, etc.).

    WordPress will happily return its front page / 404 / maintenance page with
    HTTP 200 and Content-Type: text/html when the request never reaches the
    plugin's handler. Reading the response header + a body preview makes the
    failure obvious instead of a cryptic 'non-JSON response'.
    """
    try:
        return json.loads(body_text)
    except json.JSONDecodeError:
        ctype = (content_type or "").lower()
        snippet = _sanitize_log_str(body_text or "<no body captured>", snippet_limit)
        looks_html = ("html" in ctype
                      or (body_text and "<html" in body_text[:400].lower())
                      or (body_text and "<!doctype" in body_text[:400].lower()))
        if looks_html:
            die(f"Server returned an HTML page (HTTP {http_status or '?'}, Content-Type: {content_type or 'unknown'}) "
                f"instead of JSON for {what}. "
                f"This means the request did NOT reach the plugin's handler - WordPress served a normal page "
                f"(front page, 404, maintenance, or a security-plugin block). "
                f"Check the plugin is active on that site, wp_url points to the site root "
                f"(not /wp-admin, not /wp-json, no trailing path), and no redirect/.htaccess/WAF/cache layer "
                f"is intercepting the request. "
                f"Raw body preview: {snippet}")
        die(f"Server returned a non-JSON response for {what}. "
            f"Content-Type: {content_type or 'unknown'}, HTTP {http_status or '?'}. "
            f"Raw body: {snippet}.")


def _die_http_error(e, what):
    """Handle an HTTPError from the pairing endpoints: if the server answered
    with an HTML body (the common WordPress misconfiguration), explain that
    instead of printing a bare 'HTTP 404: Not Found' line."""
    err_body = None
    try:
        err_body = _read_capped(e, 65536).decode("utf-8", errors="replace")
    except Exception:
        err_body = None
    err_ctype = e.headers.get("Content-Type", "") if e.headers else ""
    if err_body and ("html" in err_ctype.lower()
                     or "<html" in err_body[:400].lower()
                     or "<!doctype" in err_body[:400].lower()):
        die(f"Server returned HTTP {e.code} with an HTML page (Content-Type: {err_ctype or 'unknown'}) for {what}. "
            f"The request did not reach the plugin's endpoint - check the plugin is active, wp_url is correct, "
            f"and no security/redirect plugin is intercepting. "
            f"Body preview: {_sanitize_log_str(err_body, 400)}")
    die(f"Server returned HTTP {e.code}: {e.reason}")


def pair_mode(word1, word2, word3=None, config_path=None):
    """
    Phone-side insecure word-based pairing.
    
    1. Derive pairing_id from the 2 or 3 code words (same as server)
    2. Generate ephemeral X25519 keypair
    3. GET ?pair=<pairing_id> → receive server's ephemeral KX public key
    4. Compute ECDH shared secret, derive SAS words, display them
    5. Encrypt device's Ed25519 public key with the shared secret
    6. POST pairing_id + client_kx_pk + encrypted_phone_pk
    7. Wait for server admin to confirm
    """
    if not HAS_NACL:
        die("pynacl is required for pairing. Run: pip install pynacl")
    
    bits = _words_to_bits(word1, word2, word3)
    if bits is None:
        words_str = f"'{word1}' '{word2}'" + (f" '{word3}'" if word3 else "")
        die(f"Invalid code words: {words_str}. Must be from the SAS wordlist.")
    
    # 33 bits → 9 hex chars; 22 bits → 6 hex chars (legacy)
    hex_width = 9 if word3 else 6
    pairing_id = f"{bits:0{hex_width}x}"
    print(f"Pairing ID derived: {pairing_id}")
    
    # Load config to get wp_url
    if config_path is None:
        config_path = _config_path_default()
    
    cfg = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                cfg = json.load(f)
        except Exception as e:
            die(f"Failed to load config: {e}")
    
    wp_url = cfg.get("wp_url", "").strip()
    if not wp_url:
        die("wp_url not set in config. Set it first with --edit.")
    
    wp_url = wp_url.rstrip("/")
    
    # Generate ephemeral X25519 keypair
    try:
        client_kx_pk, client_kx_sk = crypto_kx_keypair()
    except Exception as e:
        die(f"Failed to generate X25519 keypair: {e}")
    
    client_kx_pk_hex = client_kx_pk.hex()
    print(f"Ephemeral KX public key: {client_kx_pk_hex[:16]}...")
    
    # Step 1: GET server's ephemeral KX public key
    get_url = f"{wp_url}/?pair={pairing_id}"
    print(f"Fetching server key: {get_url}")
    
    content_type = None
    http_status = None
    body_text = None
    try:
        ctx = _ssl_context(cfg)
        opener = _build_opener(cfg)
        req = urllib.request.Request(get_url, method="GET",
            headers={"User-Agent": "xmr-pushd/1.0", "Accept": "application/json"})
        with opener.open(req, timeout=30) as resp:
            http_status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            body = _read_capped(resp, 65536)
            body_text = body.decode("utf-8", errors="replace")
            data = _json_loads_or_die(body_text, content_type, http_status, "pairing key fetch (GET)")
    except urllib.error.HTTPError as e:
        _die_http_error(e, "pairing key fetch (GET)")
    except Exception as e:
        die(f"Failed to fetch server key: {e}")
    
    if not isinstance(data, dict):
        die(f"Unexpected server response: {data!r:.200}")
    
    if "error" in data:
        die(f"Server error: {data['error']}")
    
    server_kx_pk_hex = data.get("server_kx_pk", "")
    if not server_kx_pk_hex or len(server_kx_pk_hex) != 64:
        die(f"Invalid server_kx_pk in response: {server_kx_pk_hex!r:.80}")

    # Protocol version check: the server declares its kx_version in the GET
    # response. If missing or mismatched, the server is running an incompatible
    # plugin version - abort with a clear message instead of a cryptic decrypt_fail.
    server_kx_version = data.get("kx_version", "")
    if server_kx_version != "xmr-push-kx-v1":
        die(
            f"Protocol version mismatch: server reports kx_version={server_kx_version!r}, "
            f"this daemon expects 'xmr-push-kx-v1'. "
            f"Update the WordPress plugin to the latest version."
        )
    
    try:
        server_kx_pk = bytes.fromhex(server_kx_pk_hex)
    except ValueError:
        die("Server KX public key is not valid hex")
    
    print(f"Server KX public key: {server_kx_pk_hex[:16]}...")
    
    # Server key pinning: if we have a pinned KX public key for this server,
    # verify the received key matches. If not, abort - possible MITM.
    pinned = (cfg.get("pinned_kx_pk") or "").strip().lower()
    if pinned and len(pinned) == 64:
        if server_kx_pk_hex.lower() != pinned:
            print()
            print("=" * 60)
            print("   SERVER KEY MISMATCH - POSSIBLE MITM ATTACK!")
            print("=" * 60)
            print(f"  Pinned key:  {pinned[:16]}...{pinned[-16:]}")
            print(f"  Received:    {server_kx_pk_hex[:16]}...{server_kx_pk_hex[-16:]}")
            print()
            print("  The server's ephemeral key does not match the previously")
            print("  pinned key. This could mean:")
            print("    - A different server is responding (MITM attack)")
            print("    - The server was reinstalled/reconfigured")
            print()
            print("  If you trust this is legitimate, remove 'pinned_kx_pk'")
            print("  from your config and re-pair.")
            print("=" * 60)
            die("Server key pinning check failed - aborting for safety.")
        else:
            print(f"[OK] Server key matches pinned key (TOFU check passed)")
    else:
        print(" No pinned server key - performing Trust-On-First-Use (TOFU)")
        print("   The server key will be pinned after successful pairing.")
    
    # Pairing timeout: abort if the whole process takes too long
    pairing_deadline = time.time() + PAIRING_TIMEOUT_SECONDS
    if time.time() > pairing_deadline:
        die("Pairing timed out before ECDH computation.")
    
    # Step 2: Compute ECDH session keys (client side)
    # Use custom KDF (NOT crypto_kx_*_session_keys) for cross-compatibility
    # with sodium_compat polyfill on WordPress.
    try:
        shared_secret = crypto_scalarmult(client_kx_sk, server_kx_pk)
        # Canonical ordering of public keys (matching PHP sort)
        pks = sorted([server_kx_pk, client_kx_pk])
        session_keys = generichash(shared_secret + pks[0] + pks[1] + b'xmr-push-kx-v1', digest_size=64, encoder=RawEncoder)
        rx_key = session_keys[0:32]
        tx_key = session_keys[32:64]
    except Exception as e:
        die(f"ECDH key exchange failed: {e}")
    
    # SAS words are derived AFTER encryption below (they bind the encrypted
    # device pk, matching the PHP server). Placeholder set there.
    sas_words = None
    
    # Step 3: Encrypt device's Ed25519 public key with shared secret
    signing_pubkey_hex = (cfg.get("signing_pubkey_hex") or "").strip().lower()
    if not signing_pubkey_hex or len(signing_pubkey_hex) != 64:
        # Generate signing keys if not present
        print("No Ed25519 signing key found. Generating one now...")
        try:
            sk = SigningKey.generate()
            signing_pubkey_hex = sk.verify_key.encode(encoder=HexEncoder).decode("ascii").lower()
            signing_privkey_hex = sk.encode(encoder=HexEncoder).decode("ascii").lower()
            cfg["signing_privkey_hex"] = signing_privkey_hex
            cfg["signing_pubkey_hex"] = signing_pubkey_hex
            # Save to config
            try:
                with open(config_path, "r") as f:
                    raw = json.load(f)
                raw["signing_privkey_hex"] = signing_privkey_hex
                raw["signing_pubkey_hex"] = signing_pubkey_hex
                tmp = config_path + ".tmp"
                with open(tmp, "w") as tf:
                    json.dump(raw, tf, indent=2)
                os.chmod(tmp, 0o600)
                os.replace(tmp, config_path)
                os.chmod(config_path, 0o600)
                print(f"Signing keys saved to {config_path}")
            except Exception as e:
                print(f"Warning: Could not save signing keys to config: {e}")
        except Exception as e:
            die(f"Failed to generate Ed25519 keypair: {e}")
    
    print(f"Phone Ed25519 public key: {signing_pubkey_hex[:16]}...")
    
    # Encrypt with rx_key (the key server uses to decrypt what client sends)
    # The server (class-wc-xmr-push-pairing.php) requires the decrypted
    # plaintext to be the 64-char hex string of the device Ed25519 pk:
    #   $phone_pk_hex = sodium_crypto_secretbox_open( ... );
    #   if ( ! preg_match( '/^[0-9a-fA-F]{64}$/', $phone_pk_hex ) ) { decrypt_fail }
    # So we encrypt the ASCII hex string (64 bytes), NOT the raw 32-byte key
    # (which fails the regex and causes "decrypt_fail" on the server).
    try:
        box = SecretBox(rx_key)
        encrypted_pk = box.encrypt(signing_pubkey_hex.encode("ascii"), encoder=RawEncoder)
        encrypted_pk_b64 = base64.urlsafe_b64encode(encrypted_pk).decode("ascii").rstrip("=")
    except Exception as e:
        die(f"Encryption of public key failed: {e}")
    
    # Check timeout before POST
    if time.time() > pairing_deadline:
        die("Pairing timed out before sending data to server.")

    # Derive SAS words + paired secret binding the encrypted device pk
    # (mirrors PHP server derivation - see _pairing_keys).
    sas_words, paired_secret = _pairing_keys(rx_key, tx_key, pairing_id, encrypted_pk_b64)
    print()
    print("=" * 50)
    print("  SAS VERIFICATION WORDS (device side):")
    print(f"  >>>  {sas_words[0]}  {sas_words[1]}  {sas_words[2]}  <<<")
    print("=" * 50)
    print()
    print("The server admin sees the SAME words (both sides bind the encrypted")
    print("phone key into the SAS transcript). Read them to each other over a")
    print("separate channel (phone call, video call). They MUST match exactly.")
    print()
    
    # Step 4: POST to server
    post_data = urllib.parse.urlencode({
        "pairing_id": pairing_id,
        "client_kx_pk": client_kx_pk_hex,
        "encrypted_phone_pk": encrypted_pk_b64,
        "kx_version": "xmr-push-kx-v1",
    })
    
    post_url = f"{wp_url}/"
    print(f"Sending pairing data to server...")
    
    content_type = None
    http_status = None
    body_text = None
    try:
        opener = _build_opener(cfg)
        req = urllib.request.Request(post_url, data=post_data.encode("utf-8"), method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "xmr-pushd/1.0", "Accept": "application/json"})
        with opener.open(req, timeout=30) as resp:
            http_status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            body = _read_capped(resp, 65536)
            body_text = body.decode("utf-8", errors="replace")
            resp_data = _json_loads_or_die(body_text, content_type, http_status, "pairing data POST")
    except urllib.error.HTTPError as e:
        _die_http_error(e, "pairing data POST")
    except Exception as e:
        die(f"Failed to send pairing data: {e}")
    
    if not isinstance(resp_data, dict):
        die(f"Unexpected server response: {resp_data!r:.200}")
    
    if "error" in resp_data:
        err_msg = str(resp_data["error"])
        err_l = err_msg.lower()
        hint = ""
        if "too_many" in err_l or "too many" in err_l or "rate" in err_l:
            hint = ("\nHint: the server rate-limited this pairing attempt. "
                    "Wait for the rate-limit window and try again, then confirm on "
                    "the WordPress admin page promptly.")
        elif "already_used" in err_l or "already used" in err_l or "already paired" in err_l:
            hint = ("\nHint: these code words were already used for a pairing. "
                    "The server never reuses pairing IDs - start a new pairing "
                    "with fresh code words.")
        elif "rejected" in err_l or "canceled" in err_l or "cancelled" in err_l or "denied" in err_l:
            hint = ("\nHint: the server admin rejected/cancelled this pairing request. "
                    "Re-run pairing with fresh code words and coordinate with the admin.")
        elif "not found" in err_l or "invalid" in err_l:
            hint = ("\nHint: the server could not find this pairing. Check the code "
                    "words were entered exactly (spelling and order) and that the "
                    "pairing hasn't expired.")
        die(f"Server rejected pairing: {err_msg}{hint}")
    
    # Strictly validate server_sas: must be a list of exactly 2 or 3 words,
    # each a valid wordlist entry. Prevents a malicious server from crashing
    # pairing via type confusion or injecting ANSI escapes into the terminal.
    srv_words = resp_data.get("sas_words")
    if srv_words is not None and isinstance(srv_words, list):
        clean = []
        for w in srv_words:
            if not isinstance(w, str):
                clean = None
                break
            ws = w.strip().lower()
            if ws not in SAS_WORDLIST:
                clean = None
                break
            clean.append(ws)
        if clean is None or len(clean) not in (2, 3):
            log("Server sent malformed sas_words - treating as mismatch", "WARN")
            srv_words = None
        else:
            srv_words = clean
    elif srv_words is not None:
        log(f"Server sent non-list sas_words ({type(srv_words).__name__}) - treating as mismatch", "WARN")
        srv_words = None

    if srv_words:
        print()
        print("=" * 50)
        print("  Server's SAS words:")
        print(f"  >>>  {'  '.join(_sanitize_log_str(w, 32) for w in srv_words)}  <<<")
        print("=" * 50)
        print()
        print("Compare with your SAS words above.")
        if hmac.compare_digest(" ".join(srv_words), " ".join(list(sas_words))):
            print("[OK] SAS words MATCH! The connection is secure.")
        else:
            print("[FAIL] SAS words DO NOT MATCH! Possible MITM attack!")
            print("   Do NOT proceed. Cancel the pairing and try again.")
    
    # Persist the paired shared secret so the daemon can launch after pairing,
    # even if the server doesn't echo SAS words in this response (the session
    # may already be sas_ready server-side). This addresses xmr.txt's top
    # complaint: "launching the program checks for the shared secret first and
    # wont launch if theres no shared secret".
    #
    # The server KX public key is pinned (TOFU) ONLY when the SAS words also
    # match - pinning an unverified key would defeat the MITM check.
    if srv_words is not None and hmac.compare_digest(" ".join(srv_words), " ".join(list(sas_words))):
        try:
            with open(config_path, "r") as f:
                raw = json.load(f)
            raw["pinned_kx_pk"] = server_kx_pk_hex.lower()
            raw["shared_secret_hex"] = paired_secret.hex()
            tmp = config_path + ".tmp"
            with open(tmp, "w") as tf:
                json.dump(raw, tf, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, config_path)
            os.chmod(config_path, 0o600)
            print(f"Server KX public key pinned to config (TOFU)")
            print(f"Paired shared secret written to config - daemon can now launch")
            print(f"   Future pairings will verify against this key.")
        except Exception as e:
            print(f" Could not pin server key to config: {e}")
    else:
        # SAS echo missing or mismatched: still persist the paired secret so
        # the daemon launches, but do NOT pin the unverified server key.
        try:
            with open(config_path, "r") as f:
                raw = json.load(f)
            raw["shared_secret_hex"] = paired_secret.hex()
            tmp = config_path + ".tmp"
            with open(tmp, "w") as tf:
                json.dump(raw, tf, indent=2)
            os.chmod(tmp, 0o600)
            os.replace(tmp, config_path)
            os.chmod(config_path, 0o600)
            print(f"Paired shared secret written to config - daemon can now launch")
            if srv_words is None:
                print("   (Server did not echo SAS words; verify them on the")
                print("    WordPress admin page before confirming the pairing.)")
            else:
                print("    SAS words did not match - server key NOT pinned.")
                print("   Do NOT confirm the pairing until the words match.")
        except Exception as e:
            print(f" Could not write paired secret to config: {e}")
    
    print()
    print("Pairing data sent. The server admin must now confirm the pairing")
    print("on the WordPress Settings → Monero Push page.")
    print(f"Your Ed25519 public key: {signing_pubkey_hex}")
    print()
    print("After the admin confirms, your device will be authorized to push")
    print("signed confirmations and addresses to this server.")

if __name__ == "__main__":
    main()
