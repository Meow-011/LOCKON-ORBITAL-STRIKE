import sys
import os

print(f"Python Executable: {sys.executable}")
print(f"CWD: {os.getcwd()}")

packages = [
    "flet", "requests", "aiohttp", "bs4", "playwright", "jwt", "dns", "colorama", "PIL", "packaging"
]

for pkg in packages:
    try:
        mod = __import__(pkg)
        version = getattr(mod, "__version__", getattr(mod, "version", "UNKNOWN"))
        print(f"FOUND: {pkg}=={version} (in {os.path.dirname(mod.__file__)})")
    except ImportError as e:
        print(f"MISSING: {pkg} - {e}")
    except Exception as e:
        print(f"ERROR: {pkg} - {e}")
