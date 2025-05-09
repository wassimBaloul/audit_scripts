import requests
import concurrent.futures
import time
import datetime
import traceback
import logging
import random
import string
from jwt import encode as jwt_encode
from fpdf import FPDF
from colorama import Fore, Style, init as colorama_init
from tqdm import tqdm

colorama_init(autoreset=True)

TARGET_ENDPOINT = "http://localhost:8888"
IDOR_ENDPOINT_TEMPLATE = "http://localhost:8888/users/{id}"
VALID_TOKEN = "jwt_token"
HEADERS_BASE = {"Authorization": f"Bearer {VALID_TOKEN}"}
BASE_PAYLOAD = {"username": "testuser", "password": "testpass"}

results_log = []
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger()

def log_result(message, level="info", status=None):
    if level == "info":
        logger.info(message)
    elif level == "warn":
        logger.warning(Fore.YELLOW + message + Style.RESET_ALL)
    elif level == "error":
        logger.error(Fore.RED + message + Style.RESET_ALL)
    else:
        print(message)

    # Always store a dict in results_log
    entry = {'message': message}
    if status is not None:
        entry['status'] = status
    results_log.append(entry)

def random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def stress_test(endpoint, headers, payload, num_requests=100000, workers=1000):
    log_result(Fore.CYAN + f"\n[Aggressive Stress Test] {num_requests} requests, {workers} workers")
    start = time.time()

    session = requests.Session()

    def send_request():
        try:
            url = endpoint + f"?r={random_string(6)}"
            random_headers = headers.copy()
            random_headers["X-Random"] = random_string(12)
            r = session.post(url, json=payload, headers=random_headers, timeout=3)
            return r.status_code
        except Exception as e:
            return f"ERROR: {e}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(send_request) for _ in range(num_requests)]
        for i, future in enumerate(tqdm(concurrent.futures.as_completed(futures), total=num_requests), 1):
            status_result = future.result()
            res_message = f"[{i}/{num_requests}] -> {status_result}"
            log_result(res_message, status=status_result)

    log_result(f"Completed in {time.time() - start:.2f}s")

def generate_pdf_report_summary(results, filename="audit_summary_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Security Audit Summary Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 10, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(10)

    # Filter entries that have 'status'
    status_entries = [r for r in results if 'status' in r]

    total_requests = len(status_entries)
    success_codes = [r['status'] for r in status_entries if isinstance(r['status'], int) and 200 <= r['status'] < 300]
    fail_codes = [r['status'] for r in status_entries if isinstance(r['status'], int) and (r['status'] >= 300 or r['status'] < 200)]
    error_count = sum(1 for r in status_entries if isinstance(r['status'], str) and "ERROR" in r['status'])

    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Summary Statistics", ln=True)
    pdf.set_font("Arial", "", 12)
    pdf.cell(0, 8, f"Total Requests: {total_requests}", ln=True)
    pdf.cell(0, 8, f"Successful (2xx): {len(success_codes)}", ln=True)
    pdf.cell(0, 8, f"Failed (non-2xx): {len(fail_codes)}", ln=True)
    pdf.cell(0, 8, f"Errors/Exceptions: {error_count}", ln=True)

    pdf.ln(10)
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Sample Responses", ln=True)
    pdf.set_font("Arial", "", 10)
    sample = random.sample(status_entries, min(5, len(status_entries)))
    for idx, r in enumerate(sample, 1):
        pdf.multi_cell(0, 6, f"[Sample {idx}] {r}")

    pdf.output(filename)
    log_result(f"\n[+] PDF summary report saved as {filename}")

if __name__ == "__main__":
    log_result(Fore.MAGENTA + "\n=== Starting Aggressive Security Audit ===")
    try:
        stress_test(TARGET_ENDPOINT, HEADERS_BASE, BASE_PAYLOAD, num_requests=100000, workers=1000)
    except Exception as e:
        log_result(f"[Critical Error]: {traceback.format_exc()}", "error")
    finally:
        log_result(Fore.GREEN + "\n=== Audit Completed ===")
        generate_pdf_report_summary(results_log)
