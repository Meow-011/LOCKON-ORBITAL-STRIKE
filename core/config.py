"""
LOCKON: ORBITAL STRIKE — Configuration Manager
Centralized config read/write from config.json
"""
import os
import json

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")

DEFAULT_CONFIG = {
    "proxy": {"enabled": False, "url": "", "auth": ""},
    "scan": {"timeout": 10, "max_threads": 5, "max_crawl_pages": 15},
    "notification": {"sound": True, "desktop": True},
    "report": {"auto_generate": False, "auto_open": True, "output_dir": "reports"},
    "c2": {"default_lport": 4444}
}

_config_cache = None

def load_config():
    """Load config from disk or create with defaults."""
    global _config_cache
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                _config_cache = json.load(f)
        else:
            _config_cache = DEFAULT_CONFIG.copy()
            save_config(_config_cache)
    except (json.JSONDecodeError, OSError):
        _config_cache = DEFAULT_CONFIG.copy()
    return _config_cache

def save_config(cfg=None):
    """Write config dict to disk."""
    global _config_cache
    if cfg is not None:
        _config_cache = cfg
    if _config_cache is None:
        _config_cache = DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(_config_cache, f, indent=4, ensure_ascii=False)
    except OSError as e:
        print(f"[!] Config save error: {e}")

def get(key, default=None):
    """
    Dot-notation accessor for config values.
    Example: get("proxy.url") -> config["proxy"]["url"]
    """
    global _config_cache
    if _config_cache is None:
        load_config()
    
    keys = key.split(".")
    val = _config_cache
    try:
        for k in keys:
            val = val[k]
        return val
    except (KeyError, TypeError):
        return default

def set_value(key, value):
    """
    Dot-notation setter for config values.
    Example: set_value("proxy.url", "http://127.0.0.1:8080")
    """
    global _config_cache
    if _config_cache is None:
        load_config()
    
    keys = key.split(".")
    obj = _config_cache
    for k in keys[:-1]:
        if k not in obj:
            obj[k] = {}
        obj = obj[k]
    obj[keys[-1]] = value
    save_config()
