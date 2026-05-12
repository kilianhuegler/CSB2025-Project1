# CSB Project 1 — Vulnerable Web Application

> **WARNING:** This application is intentionally vulnerable.


## OWASP Top 10 2021 - Mapping

| #      | OWASP category                                          | Location                                               |
| ------ | ------------------------------------------------------- | ------------------------------------------------------ |
| Flaw 1 | A03:2021 Injection (Server-Side Template Injection)     | `webapp/src/app.py`, `admin_log_viewer()`              |
| Flaw 2 | A08:2021 Software and Data Integrity Failures           | `webapp/src/app.py`, `load_notes()` / `save_notes()`   |
| Flaw 3 | A01:2021 Broken Access Control                          | `webapp/src/app.py`, `/admin/*` routes + `robots.txt`  |
| Flaw 4 | A02:2021 Cryptographic Failures                         | `webapp/src/app.py`, `ADMIN_PASSWORD_HASH` + `login()` |
| Flaw 5 | A09:2021 Security Logging and Monitoring Failures       | `webapp/src/app.py`, `login()`                         |

Each flaw is annotated with a comment block of the form:

```python
# === Flaw N: <OWASP category> ===
# ...
<vulnerable code>
# === FIX for Flaw N ===
# ...
# <fix code>
```

## Installation and Running

### Docker

```bash
docker compose up --build
```

The application is reachable at <http://localhost:5000/>.

To stop and remove the container:

```bash
docker compose down
```

## Default Credentials

username: admin
password: admin123

## Screenshots

The `screenshots/` folder contains before/after png files for each flaw.