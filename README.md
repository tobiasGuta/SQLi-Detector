# SQLi Detector

> **A fast, safe, and colorful Detection-only SQL Injection Scanner.**
> *Proves a vulnerability exists. Never exploits it.*

SQLi Detector is a lightweight Python-based command-line tool designed for bug bounty hunters, penetration testers, and developers. Unlike heavy exploitation frameworks (like `sqlmap`) that actively extract data or execute commands, this tool is strictly limited to **detection only**. It ensures you stay safely within the rules of engagement and minimizes the risk of impacting target environments.

---

## Features

- **3 Advanced Detection Techniques**: Checks for Error-based, Boolean-based blind, and Time-based blind vulnerabilities all in one pass.
- **Rich Colorful Terminal Output**: Beautifully formatted terminal summaries with clear, colorful mapping of findings, payloads, and evidence. 
- **Payload Visibility**: The terminal and reports show you *exactly* which payload string triggered the vulnerability (e.g., the specific `True`/`False` probe, or the exact error byte).
- **JSON Reporting**: Automatically logs findings into a structured `./reports/` directory with confidence metrics and DBMS fingerprints.
- **Strict Scope Enforcement**: Built-in scoping ensures your tool will strictly bound itself to specific hosts, preventing accidental out-of-scope scanning.
- **Safety First**: Proves the vulnerability without dumping tables, avoiding UNION extractions, stacked queries, or DDL/DML execution (`DROP`, `UPDATE`, `INSERT`, `DELETE`).
- **Flexible Interactions**: Handles GET queries, POST bodies, custom headers, and session cookies out-of-the-box.

---

## Installation

Requirements are incredibly light! You just need Python 3 and the `requests` library.

```bash
# Clone the repository
git clone https://github.com/tobiasGuta/SQLi-Detector.git
cd SQLi-Detector

# Install the HTTP request library
pip3 install requests
```

---

## Usage Guide

### 1. Basic GET Parameter Scan
Provide the URL with parameters and restrict to the scope:
```bash
python3 cli.py \
  --url "http://testphp.vulnweb.com/listproducts.php?cat=1" \
  --scope "testphp.vulnweb.com"
```

### 2. POST Form Data Scan
Pass data directly to endpoints (e.g., login forms) via `--data` and `--method POST`:
```bash
python3 cli.py \
  --url "http://10.67.152.199/portal.php" \
  --method POST \
  --data "searchitem=agent" \
  --scope "10.67.152.199" 
```

### 3. Scanning Behind Authentication (Adding Cookies & Headers)
Often, you need to test internal endpoints as an authenticated user:
```bash
python3 cli.py \
  --url "http://target.com/profile?id=5" \
  --scope "target.com" \
  --cookies "PHPSESSID=4dseuqhb5e6plc6ugiqnk53o44" "user_pref=dark" \
  --headers "Authorization: Bearer xyz123"
```

### 4. Selecting Specific Techniques
If the server is reacting badly to Time-based testing, just restrict the tool to boolean and error checks:
```bash
python3 cli.py --url "http://target.com/page?id=1" --scope target.com --techniques error boolean
```

---

## Command-Line Options

| Flag / Option | Description |
|---|---|
| `--url` | Target URL to test **(required)**. |
| `--method` | HTTP method: `GET` or `POST` (default: `GET`). |
| `--data` | POST body payload string (e.g., `'param=value&param2=value2'`). |
| `--scope` | Allowed hosts or patterns to strictly limit testing to. |
| `--techniques` | Which techniques to use: `error`, `boolean`, `time` (default: runs all). |
| `--headers` | Append custom headers (e.g., `--headers "X-Custom: value"`). |
| `--cookies` | Append session cookies (e.g., `--cookies "name=value"`). |
| `--timeout` | Request timeout limit in seconds (default: 10s). |
| `--delay` | Delay between consecutive requests to not hammer the server (default: 0.5s). |
| `--output` | Provide a custom path/name for the generated JSON report. |
| `-y`, `--yes` | Skip authorization confirmation prompt. |
| `-v`, `--verbose`| Enable verbose debug logging. |

---

## How It Works: The Detection Techniques

### 1. Error-Based
Injects characters that break the SQL string context (`'`, `"`, `\`) and pattern-matches the HTTP response against detailed DBMS error signatures (e.g., typical MySQL syntax errors, PostgreSQL mapping errors). If a signature gets reflected, the tool parses out the specific **DBMS fingerprint** for you.

### 2. Boolean-Based Blind
Injects `TRUE` (e.g., `AND 1=1`) vs `FALSE` (e.g., `AND 1=2`) logic conditions and compares the length and structural similarity of the resulting page response. A true condition should render normally; a false condition should structurally deviate.

### 3. Time-Based Blind
Injects time-delay probes specific per DBMS (e.g., `SLEEP(5)`, `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'`) and carefully monitors the server's HTTP response time. If a statistical delay significantly exceeds the baseline latency threshold, a Time-based vulnerability is flagged.

---

## Interpreting the Output

When a scan finishes, SQLi Detector outputs a colorized summary to your terminal that reveals:
- The parameters successfully tested.
- How many injections were confirmed.
- The specific Injection technique.
- The **payloads** used to trigger the confirmation.
- The inferred **DBMS backend**.

The tool also saves all structured results into an easy-to-parse JSON file inside the **`./reports`** directory, ideal for mapping into external tools or platforms.

**Exit Codes:**
- `0` Clean, no SQL injection logic found.
- `1` Scan error (scope violation, bad arguments, missing parameters).
- `2` **Vulnerability Found** (Confirmed detection).

---

## Legal Disclaimer

**Only use this tool on systems you explicitly own or have explicit, written permission to test.**
Unauthorized scanning may fall under and violate laws equivalent to the **Computer Fraud and Abuse Act (CFAA)** or the **UK Computer Misuse Act**, depending on your jurisdiction. 

This tool was created exclusively to help:
- **Developers** securing their own web applications.
- **Bug bounty hunters** evaluating endpoints inside authorized scopes.
- **Penetration testers** operating strictly under signed Statements of Work/Rules of Engagement.
