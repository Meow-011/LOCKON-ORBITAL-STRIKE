import sys
import os

print(f"Propelling CWD: {os.getcwd()}")
print(f"Path: {sys.path}")

try:
    print("Attempting to import modules.active.cve_sniper...")
    import modules.active.cve_sniper
    print("SUCCESS: Imported cve_sniper module")
except Exception as e:
    print(f"FAILED module import: {e}")

try:
    print("Attempting to import run_cve_scan from modules.active.cve_sniper...")
    from modules.active.cve_sniper import run_cve_scan
    print("SUCCESS: Imported run_cve_scan function")
except Exception as e:
    print(f"FAILED function import: {e}")
