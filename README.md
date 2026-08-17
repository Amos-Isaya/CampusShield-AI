# CampusShield AI

CampusShield AI is a full-stack cybersecurity incident reporting and triage platform for college communities. Students can submit suspicious messages or account concerns, receive immediate safety guidance, and follow the investigation. Authorized analysts can prioritize reports, manage incident status, review threat trends, and inspect an immutable-style activity trail.

## Live demo

**[Open the interactive CampusShield AI demo](https://amos-isaya.github.io/CampusShield-AI/)**

The public GitHub Pages version uses a clearly isolated browser demo data layer because GitHub Pages cannot execute the Python server. It supports both roles, report submission, triage, incident management, analytics, and audit activity. The repository's Python application is the full backend implementation with hashed authentication, SQLite persistence, authorization, and server-side validation.

## Why this project is different

This is a working application rather than a static interface. It includes a browser client, authenticated API, relational database, risk-analysis engine, role-based workflows, analytics, and security controls while remaining dependency-free.

## Features

- Student and security-analyst roles
- Secure password hashing with PBKDF2-HMAC-SHA256
- Random, expiring bearer sessions stored as hashes
- Login rate limiting
- Incident submission with privacy guidance and input validation
- Explainable risk scores, threat indicators, and recommended actions
- Analyst queue and incident lifecycle management
- Threat category and severity analytics
- Security audit activity
- Responsive desktop and mobile interface
- Content Security Policy and defensive HTTP headers
- SQLite persistence

## Run locally

Requirements: Python 3.10 or newer. No packages need to be installed.

```bash
cd CampusShield-AI
python3 server.py
```

Open [http://127.0.0.1:8080](http://127.0.0.1:8080).

### Demo accounts

| Role | Email | Password |
|---|---|---|
| Student | `student@campus.edu` | `Demo123!` |
| Security analyst | `analyst@campus.edu` | `Admin123!` |

These credentials are development fixtures. Replace the seed accounts before any real deployment.

## Architecture

```text
CampusShield-AI/
├── server.py             # HTTP API, authentication, triage, and SQLite access
├── public/
│   ├── index.html        # Student and analyst interfaces
│   ├── styles.css        # Responsive product design
│   └── app.js            # API client and application state
├── tests/
│   └── test_server.py    # Risk-engine and authentication tests
├── .gitignore
└── README.md
```

## API

| Method | Endpoint | Access | Purpose |
|---|---|---|---|
| `POST` | `/api/login` | Public | Create an authenticated session |
| `POST` | `/api/logout` | Signed in | Revoke the current session |
| `GET` | `/api/me` | Signed in | Get the current user |
| `GET` | `/api/incidents` | Signed in | List permitted incidents |
| `POST` | `/api/incidents` | Signed in | Analyze and submit a report |
| `PATCH` | `/api/incidents/:id` | Analyst | Update incident status |
| `GET` | `/api/stats` | Analyst | Retrieve threat analytics |
| `GET` | `/api/audit` | Analyst | Retrieve security activity |

## Security model

CampusShield treats automated analysis as decision support, not a final verdict. Every result identifies its rule-based method and directs users toward human verification.

Current safeguards include least-privilege data access, parameterized SQL, output escaping, strict input limits, login throttling, hashed sessions, short session expiration, and restrictive response headers. Production deployment should additionally use HTTPS behind a reverse proxy, managed secrets, encrypted backups, institutional identity/SSO, malware scanning in an isolated service, centralized logs, and a formal retention policy.

Do not submit real passwords, financial information, health records, government identifiers, or other unnecessary personal data.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

## Next steps

- Add institutional SSO and multifactor authentication
- Integrate a sandboxed URL/file reputation provider
- Add notifications and analyst assignments
- Store attachments in quarantined object storage
- Add an optional secured language-model provider
- Create evaluation datasets for false-positive and false-negative analysis
- Containerize and deploy behind a production application server

## Disclaimer

CampusShield AI is an educational project. It is not a replacement for professional incident response, campus emergency procedures, or law enforcement.
