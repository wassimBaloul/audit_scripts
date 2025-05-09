# Security Audit Scripts

## Overview

This repository contains two Python scripts designed for automated security auditing of web applications.

- **script.py**: Performs a comprehensive security audit, including stress testing, input fuzzing, protocol manipulation, authentication bypass testing, and IDOR testing. It generates a detailed PDF report summarizing the findings.
    
- **script2.py**: Focuses on an aggressive stress test to evaluate the application's resilience under high load. It provides a summary PDF report highlighting the test results.
    

---

## Prerequisites

- Python packages:
    
    - `requests`
        
    - `concurrent.futures` (Built-in for Python 3.2+)
        
    - `fpdf`
        
    - `colorama`
        
    - `tqdm`
        
    - `pyjwt` (for JWT encoding)
        

To install required packages:

```bash
`pip install requests fpdf colorama tqdm pyjwt`
```
---

## Configuration

### Configuration Settings

- **TARGET_ENDPOINT**: The base URL of the target application (e.g., `http://localhost:8888`).
    
- **IDOR_ENDPOINT_TEMPLATE**: Template URL for IDOR testing (e.g., `http://localhost:8888/users/{id}`).
    
- **VALID_TOKEN**: A valid JWT token for authenticated requests.
    
- **HEADERS_BASE**: Base headers, including the Authorization token.
    
- **BASE_PAYLOAD**: Sample payload for testing (e.g., `{"username": "testuser", "password": "testpass"}`).
    

---

## Script Breakdown

### `script.py`

#### Description

`script.py` performs a series of security tests on the target application and generates a detailed PDF report.

#### Features

1. **Stress Test (DoS)**: Sends multiple concurrent requests to evaluate the application's performance under load.
    
2. **Fuzzing Inputs**: Tests the application with various malicious inputs to identify potential vulnerabilities.
    
3. **Protocol Manipulation**: Sends requests with unusual HTTP methods and headers to test the application's protocol handling.
    
4. **Authentication Bypass Testing**: Attempts to access protected resources using invalid or missing tokens.
    
5. **IDOR Testing**: Checks for Insecure Direct Object References by accessing user data with different IDs.
    
6. **PDF Report Generation**: Compiles the results into a comprehensive PDF report.
    

#### Usage

To run the script, use the following command:

```bash
`python script.py`
```
---

### `script2.py`

#### Description

`script2.py` conducts an aggressive stress test on the target application and generates a summary PDF report.

#### Features

- **Aggressive Stress Test**: Sends a high volume of concurrent requests with randomized headers and parameters to simulate heavy load conditions.
    
- **PDF Summary Report**: Provides a concise summary of the test results, including success and failure rates.
    

#### Usage

To run the script, use the following command:
```bash
`python script2.py`
```
---

## Notes

- Ensure the target application is running and accessible at the specified `TARGET_ENDPOINT`.
    
- Replace `VALID_TOKEN` with a valid JWT token to authenticate requests.
    
- Modify `BASE_PAYLOAD` as needed to match the application's expected input.
    
- Use caution when performing aggressive stress tests to avoid unintended disruption of services.
