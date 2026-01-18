import re
from gui.theme import *

def sanitize_log_message(message):
    """
    Sanitizes log messages and determines the color based on content.
    Returns (clean_message, color_hex)
    """
    # Remove some special characters but keep structure
    message = re.sub(r'[^\w\s,.:;/\-_()\[\]\'\"=@]', '', message)
    
    if "CRITICAL" in message or "ERROR" in message:
        return f"[ERR] {message.strip()}", COLOR_SEV_CRITICAL
    elif "Warning" in message or "Vulnerable" in message:
        return f"[WRN] {message.strip()}", COLOR_SEV_MEDIUM
    elif "Successfully" in message or "Completed" in message:
        return f"[OK]  {message.strip()}", COLOR_SEV_LOW
    elif "Phase" in message:
        return f"► {message.strip()}", "#FFFFFF"
    elif "Exploit" in message or "FOUND" in message:
        return f"[+] {message.strip()}", COLOR_SEV_INFO
    else:
        return f"[INF] {message.strip()}", COLOR_TEXT_DIM
