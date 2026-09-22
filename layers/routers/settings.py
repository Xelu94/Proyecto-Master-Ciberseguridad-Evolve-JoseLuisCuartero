from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import os

from layers.routers_functions import _read_env_file, _mask, _write_env_file, load_dotenv, _runtime_dir, SettingsIn


router = APIRouter()


SETTINGS_KEYS = [
    "ANTHROPIC_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "MALWAREBAZAAR_API_KEY",
    "HUNTER_API_KEY",
    "SHODAN_API_KEY",
    "URLSCAN_API_KEY",
    "HIBP_API_KEY",
    "LEAKRADAR_API_KEY",
    "ANYRUN_API_KEY",
]


@router.get("/api/settings")
def get_settings():
    pairs = _read_env_file()
    result = {}
    for k in SETTINGS_KEYS:
        val = pairs.get(k, "")
        result[k] = {"masked": _mask(val), "set": bool(val)}
    return result


RUNTIME_DIR = _runtime_dir()

load_dotenv(dotenv_path=RUNTIME_DIR / ".env", encoding="utf-8", override=True)
(RUNTIME_DIR / "data").mkdir(exist_ok=True)


@router.post("/api/settings")
def save_settings(data: SettingsIn):
    # Only allow whitelisted keys
    filtered = {k: v for k, v in data.keys.items() if k in SETTINGS_KEYS}
    if not filtered:
        raise HTTPException(400, "No valid keys provided")

    _write_env_file(filtered)

    # Reload into current process environment + dependent modules
    load_dotenv(dotenv_path=RUNTIME_DIR / ".env", encoding="utf-8", override=True)
    import claude_service as _ai
    import osint_tools as _osint
    _ai.client = None  # force re-init on next call
    # Reload API keys in osint module
    for k in filtered:
        val = os.getenv(k, "")
        if k == "SHODAN_API_KEY":
            _osint.SHODAN_KEY = val
        elif k == "VIRUSTOTAL_API_KEY":
            _osint.VT_KEY = val
        elif k == "HUNTER_API_KEY":
            _osint.HUNTER_KEY = val
        elif k == "URLSCAN_API_KEY":
            _osint.URLSCAN_KEY = val
        elif k == "ABUSEIPDB_API_KEY":
            _osint.ABUSEIPDB_KEY = val
        elif k == "MALWAREBAZAAR_API_KEY":
            _osint.MALWAREBAZAAR_KEY = val
        elif k == "HIBP_API_KEY":
            _osint.HIBP_KEY = val
        elif k == "LEAKRADAR_API_KEY":
            _osint.LEAKRADAR_KEY = val
        elif k == "ANYRUN_API_KEY":
            _osint.ANYRUN_KEY = val

    return {"saved": list(filtered.keys())}