import os
import sys
import platform
import zipfile
import tarfile
import shutil
import urllib.request
import subprocess

# Determine Project Paths
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__)) # [FIX] Use absolute path
BIN_DIR = os.path.join(PROJECT_DIR, "bin")
os.makedirs(BIN_DIR, exist_ok=True)

OS_TYPE = platform.system().lower() # windows, linux, darwin
ARCH = platform.machine().lower()   # amd64, x86_64, arm64

# [FIX] Helper to log to both console and UI if callback provided
def log_msg(msg, callback=None):
    print(msg)
    if callback:
        callback(msg)

def download_file(url, dest, callback=None):
    log_msg(f"⬇️ Downloading: {url}", callback)
    try:
        opener = urllib.request.build_opener()
        opener.addheaders = [('User-agent', 'Mozilla/5.0')]
        urllib.request.install_opener(opener)
        urllib.request.urlretrieve(url, dest)
        log_msg("✅ Download complete.", callback)
        return True
    except Exception as e:
        log_msg(f"❌ Download failed: {e}", callback)
        return False

def extract_archive(file_path, extract_to, callback=None):
    try:
        log_msg(f"📦 Extracting {os.path.basename(file_path)}...", callback)
        if file_path.endswith(".zip"):
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        elif file_path.endswith(".tar.gz"):
            with tarfile.open(file_path, "r:gz") as tar:
                tar.extractall(extract_to)
        log_msg("✅ Extracted successfully.", callback)
        os.remove(file_path)
    except Exception as e:
        log_msg(f"❌ Extraction failed: {e}", callback)

def setup_playwright(callback=None):
    log_msg("\n[1/3] Checking Playwright Browsers...", callback)
    try:
        subprocess.run(["playwright", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_msg("✅ Playwright is installed. Ensuring browsers...", callback)
        # Install chromium only to save time/space
        subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
        log_msg("✅ Chromium installed/updated.", callback)
    except Exception as e:
        log_msg(f"⚠️ Playwright issue: {e}. Attempting to fix...", callback)
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "playwright"], check=True)
            subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], check=True)
            log_msg("✅ Playwright fixed.", callback)
        except Exception as ex:
            log_msg(f"❌ Failed to install Playwright: {ex}", callback)

def setup_subfinder(callback=None):
    log_msg("\n[2/3] Checking Subfinder...", callback)
    exe_name = "subfinder.exe" if "windows" in OS_TYPE else "subfinder"
    if os.path.exists(os.path.join(BIN_DIR, exe_name)):
        log_msg("✅ Subfinder is ready.", callback)
        return

    url = ""
    if "windows" in OS_TYPE:
        url = "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_windows_amd64.zip"
    elif "linux" in OS_TYPE:
        url = "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip"
    elif "darwin" in OS_TYPE:
        url = "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_macOS_amd64.zip"

    if url:
        if download_file(url, os.path.join(BIN_DIR, "subfinder.zip"), callback):
            extract_archive(os.path.join(BIN_DIR, "subfinder.zip"), BIN_DIR, callback)
    else:
        log_msg("❌ OS not supported for auto-download.", callback)

def setup_nuclei(callback=None):
    log_msg("\n[3/3] Checking Nuclei...", callback)
    exe_name = "nuclei.exe" if "windows" in OS_TYPE else "nuclei"
    if os.path.exists(os.path.join(BIN_DIR, exe_name)):
        log_msg("✅ Nuclei is ready.", callback)
        return

    url = ""
    if "windows" in OS_TYPE:
        url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_windows_amd64.zip"
    elif "linux" in OS_TYPE:
        url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip"
    elif "darwin" in OS_TYPE:
        url = "https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_macOS_amd64.zip"

    if url:
        if download_file(url, os.path.join(BIN_DIR, "nuclei.zip"), callback):
            extract_archive(os.path.join(BIN_DIR, "nuclei.zip"), BIN_DIR, callback)

def setup_nmap(callback=None):
    # Nmap is hard to install portably, just check
    if shutil.which("nmap"):
        log_msg("✅ Nmap is detected in system.", callback)
    else:
        log_msg("⚠️ Nmap NOT found. Port scan might fail.", callback)
            log_msg("👉 Please install Nmap manually from nmap.org", callback)

def check_python_packages(callback=None):
    log_msg("\n[0/4] Verifying Python Libraries...", callback)
    req_file = os.path.join(PROJECT_DIR, "requirements.txt")
    if not os.path.exists(req_file):
        log_msg("⚠️ requirements.txt not found. Skipping library check.", callback)
        return

    try:
        import pkg_resources
        with open(req_file, 'r') as f:
            requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        missing = []
        for req in requirements:
            try:
                pkg_resources.require(req)
            except (pkg_resources.DistributionNotFound, pkg_resources.VersionConflict):
                missing.append(req)
        
        if missing:
            log_msg(f"❌ Missing Libraries: {', '.join(missing)}", callback)
            log_msg("⚡ Attempting auto-install...", callback)
            try:
                subprocess.run([sys.executable, "-m", "pip", "install", "-r", req_file], check=True)
                log_msg("✅ Libraries (re)installed successfully.", callback)
            except Exception as e:
                log_msg(f"❌ Auto-install failed: {e}", callback)
        else:
            log_msg("✅ All Python libraries are installed.", callback)
            
    except ImportError:
        log_msg("⚠️ pkg_resources not found. Cannot verify versions.", callback)
    except Exception as e:
        log_msg(f"⚠️ Lib check error: {e}", callback)

def check_dependencies(callback=None):
    log_msg("🛠️ Starting Dependency Check...", callback)
    check_python_packages(callback) # [NEW]
    setup_playwright(callback)
    setup_subfinder(callback)
    setup_nuclei(callback)
    setup_nmap(callback)
    log_msg("✨ Setup Completed!", callback)

if __name__ == "__main__":
    check_dependencies()