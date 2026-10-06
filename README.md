# FileSentry

**Binary File Forensics & File-Type Intelligence Platform**

FileSentry is a portfolio-grade defensive security application that determines a file's likely true format from binary signatures, compares it with the claimed filename extension, calculates cryptographic hashes and entropy, scores forensic risk using explainable rules, and generates a case report.

> **Safety:** FileSentry treats uploaded samples as untrusted data. The analysis pipeline reads bytes only; it never executes uploaded files.

## Highlights

- Magic-number / binary-signature identification
- Extension-vs-content mismatch detection
- SHA-256 / SHA-512 / MD5 hashing
- Shannon entropy analysis
- Basic PE / ELF structural indicators
- Explainable risk scoring with finding-level evidence
- JWT authentication with memory-safe password derivation via `scrypt`
- PostgreSQL-ready SQLAlchemy persistence (SQLite works out of the box)
- React + TypeScript dashboard
- PDF forensic report generation
- Docker Compose deployment and GitHub Actions CI
- API-first architecture for future ML/threat-intelligence integrations

## Architecture

```text
React + TypeScript
        |
        v
FastAPI REST API ---- JWT Auth
        |
        +---- Analysis Engine
        |       +---- Signature detector
        |       +---- Hashing
        |       +---- Entropy
        |       +---- Structure checks
        |       +---- Risk engine
        |
        +---- SQLAlchemy ---- PostgreSQL / SQLite
        |
        +---- PDF report
```

Docker Compose follows the current Compose Specification; no obsolete top-level `version` key is used. See Docker's current Compose reference.  

## Quick start

### Local

```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for the API and `http://127.0.0.1:8000/health` for a health check.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Set `VITE_API_URL=http://127.0.0.1:8000` if the API is not on the default URL.

### Docker Compose

```bash
docker compose up --build
```

Services: frontend, API, PostgreSQL.

## API flow

1. Register/login to obtain a bearer token.
2. Upload a file to `POST /api/v1/analyses`.
3. The server stores the sample in a non-executable quarantine directory and analyzes bytes only.
4. Poll `GET /api/v1/analyses/{id}`.
5. Download `GET /api/v1/analyses/{id}/report`.

## Security controls in this release

- Upload size cap (`MAX_UPLOAD_MB`)
- Filename normalization
- UUID storage names, not user-provided paths
- File contents never passed to a shell
- No execution of uploaded content
- JWT-protected analysis endpoints
- Password hashing with `scrypt`
- CORS allow-list
- Security headers in API responses
- SQLAlchemy ORM instead of string-built SQL
- Automatic quarantine cleanup can be enabled later without changing the API contract

## Roadmap to 10/10

The foundation is intentionally built for the next releases:

- async job queue with Redis/Celery
- YARA rule integration in an isolated worker
- richer PE/ELF/PDF/Office parsers
- case management and evidence chain-of-custody
- STIX/TAXII/VT correlation
- statistical anomaly detection for files
- ML-assisted file classification with calibrated confidence
- OpenTelemetry metrics/traces
- object storage (S3-compatible) with retention policies
- RBAC and audit logging

## License

MIT — see `LICENSE`.

## Demo dataset

Generate two synthetic, non-malicious samples:

```bash
python scripts/make_demo_samples.py
```

`sample-files/invoice.jpg` deliberately contains a tiny synthetic `MZ`/`PE` signature while keeping the `.jpg` name, so the UI can demonstrate extension mismatch without requiring real malware.

## Current implementation status

**Release 0.1:** authentication, secure upload handling, signature detection, hashing, entropy, PE/ELF indicators, risk scoring, database persistence, PDF reporting, React dashboard, tests, Docker Compose, and CI are implemented.

The ML/YARA/sandbox components are intentionally future modules rather than fake “AI” features. That keeps the current evidence chain explainable and safe.
