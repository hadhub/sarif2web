# Sarif2Web

A web-based application for managing and reviewing security findings from [SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) and JSON files. **Centralized interface for analyzing, filtering, tracking, and exporting security analysis results.**

## Supported Tools

| Tool               | Status   | Command                                                                       |
| ------------------ | -------- | ----------------------------------------------------------------------------- |
| Semgrep / Opengrep | Tested   | `semgrep scan --sarif --sarif-output=scan.sarif`                              |
| CodeQL             | Tested   | `codeql database analyze codeql-db --format=sarif-latest --output=scan.sarif` |
| Snyk               | Tested   | `snyk test --sarif-file-output=scan.sarif`                                    |
| Gitleaks           | Tested   | `gitleaks detect --source=. --report-format=sarif --report-path=scan.sarif`   |
| TruffleHog         | Tested   | `trufflehog git https://github.com/repo.git --json > results.jsonl`           |

Any tool that outputs valid SARIF should work.

## Screenshots

Dashboard
![Dashboard dark](screenshots/s1.png)

Filters & triage 
![Filters](screenshots/s4.png)

Graph view
![Graph](screenshots/s3.png)

Drag & drop upload
![Upload](screenshots/s5.png)

## Features

- **Drag & drop upload** -- drop `.sarif` or `.json` files anywhere on the page; auto-creates a project if none is selected
- **Multi-format support** -- SARIF, gitleaks JSON, TruffleHog JSONL
- **Multi-file projects** -- merge multiple scan files into one project with automatic deduplication
- **Integrated scanning** -- launch scans directly from the UI by providing a Git repository URL (see [Integrated Scanners](#integrated-scanners))
- **Settings & tokens** -- configure API tokens (Semgrep, Snyk, GitHub) via the Settings modal (gear icon); tokens are stored in MongoDB and persist across restarts
- **Filter bar** -- one-click filtering by severity, status, and tool directly from the stats bar or table cells
- **Search** -- full-text search across rule IDs, file paths, messages, and code snippets
- **Status tracking** -- triage findings as New, Confirmed, False Positive, Mitigated, or Accepted Risk
- **Bulk operations** -- select multiple findings to update status or delete in bulk
- **Soft delete + undo** -- deleted findings can be restored via the undo toast within 6 seconds
- **Notes** -- annotate individual findings for documentation
- **SVG code flow graphs** -- visualize source-to-sink data flows and finding locations
- **SARIF export** -- re-export findings with embedded review metadata (status + notes)
- **Dark / Light theme** -- Dracula dark and clean light themes, persisted in local storage

## Quick Start

```bash
docker-compose up --build
```

App available at **http://localhost:9090**

```bash
docker-compose down        # stop services
docker-compose down -v     # stop + wipe database
```

## Architecture

```
Browser --> Nginx (:9090) --> Flask/Gunicorn (:5000) --> MongoDB (:27017)
```

| Service       | Role                                            |
| ------------- | ----------------------------------------------- |
| **Nginx**     | Reverse proxy, 50 MB upload limit, 120s timeout |
| **Flask**     | Python 3.12 app server, 2 Gunicorn workers      |
| **MongoDB 7** | Document store, persistent Docker volume        |

## Project Structure

```
sarif2web/
├── app/
│   ├── app.py              # Flask backend (routes, parsers, SVG renderer)
│   ├── requirements.txt    # Python dependencies
│   └── templates/
│       └── index.html      # Frontend SPA (vanilla JS, no build step)
├── nginx/
│   └── nginx.conf          # Reverse proxy config
├── Dockerfile              # App container
└── docker-compose.yml      # Service orchestration
```

## Integrated Scanners

The app can clone a Git repository and run scanners directly from the UI. Click the **Scan** button, provide a repo URL, and select a scanner.

| Scanner    | Token required | Behavior                                                                                      |
| ---------- | -------------- | --------------------------------------------------------------------------------------------- |
| Semgrep    | Optional       | Without token: `semgrep scan` with default rules. With token: `semgrep ci` with Cloud rules.  |
| Snyk       | **Required**   | Requires a Snyk API token. Scans are blocked if no token is configured.                       |
| CodeQL     | No             | Detects language automatically, creates a CodeQL database, and runs analysis.                  |
| TruffleHog | No             | Scans the filesystem for leaked secrets.                                                      |
| Gitleaks   | No             | Fast regex + entropy-based secret detection.                                                  |

### Settings & API Tokens

Click the **gear icon** (&#9881;) in the toolbar to open the Settings modal. Tokens are stored in MongoDB and persist across container restarts.

| Token           | Purpose                                                                 |
| --------------- | ----------------------------------------------------------------------- |
| Semgrep Token   | Enables `semgrep ci` with Semgrep Cloud Platform rules and policies     |
| Snyk Token      | Required to authenticate Snyk CLI (`snyk code test`)                    |
| GitHub Token    | Allows cloning private repositories via HTTPS                           |

- Tokens are displayed masked (e.g. `••••abcd`) when set
- Use the **X** button next to a token field to remove it
- If a scan requires a missing token, an error message directs the user to the Settings modal

## Configuration

| Variable    | Default                               | Description               |
| ----------- | ------------------------------------- | ------------------------- |
| `MONGO_URI` | `mongodb://mongo:27017/sarif_manager` | MongoDB connection string |

## API Reference

| Method   | Endpoint                    | Description                                                  |
| -------- | --------------------------- | ------------------------------------------------------------ |
| `POST`   | `/api/projects`             | Create a project                                             |
| `GET`    | `/api/projects`             | List projects                                                |
| `DELETE` | `/api/projects/<id>`        | Delete a project + findings                                  |
| `POST`   | `/api/projects/bulk-delete` | Bulk delete projects                                         |
| `POST`   | `/api/upload`               | Upload file (multipart: `file` + `project_id`)               |
| `GET`    | `/api/findings`             | List findings (`project_id`, `status`, `level`, `tool`, `q`) |
| `GET`    | `/api/findings/counts`      | Unfiltered counts by level, status, tool                     |
| `PATCH`  | `/api/findings/<id>`        | Update status or notes                                       |
| `PATCH`  | `/api/findings/bulk`        | Bulk update statuses                                         |
| `POST`   | `/api/findings/bulk-delete` | Soft-delete findings                                         |
| `POST`   | `/api/findings/restore`     | Restore soft-deleted findings                                |
| `GET`    | `/api/findings/<id>/svg`    | SVG code flow visualization                                  |
| `GET`    | `/api/export/<project_id>`  | Export as SARIF                                              |
| `GET`    | `/api/scanners`             | List available scanners                                      |
| `POST`   | `/api/scans`                | Launch a scan (repo URL + scanner)                           |
| `GET`    | `/api/scans`                | List scans for a project                                     |
| `GET`    | `/api/scans/<id>`           | Get scan status and details                                  |
| `DELETE` | `/api/scans/<id>`           | Delete a scan record                                         |
| `GET`    | `/api/settings`             | Get settings (tokens masked)                                 |
| `PUT`    | `/api/settings`             | Update settings (tokens)                                     |

### Examples

```bash
# Create a project
curl -X POST http://localhost:9090/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "my-audit"}'

# Upload a SARIF file
curl -X POST http://localhost:9090/api/upload \
  -F "file=@results.sarif" \
  -F "project_id=<project_id>"

# List findings with filters
curl "http://localhost:9090/api/findings?project_id=<id>&level=error&status=new&tool=Semgrep"

# Bulk update statuses
curl -X PATCH http://localhost:9090/api/findings/bulk \
  -H "Content-Type: application/json" \
  -d '{"ids": ["id1", "id2"], "status": "false_positive"}'

# Soft-delete + restore
curl -X POST http://localhost:9090/api/findings/bulk-delete \
  -H "Content-Type: application/json" \
  -d '{"ids": ["id1", "id2"]}'

curl -X POST http://localhost:9090/api/findings/restore \
  -H "Content-Type: application/json" \
  -d '{"ids": ["id1", "id2"]}'

# Export
curl http://localhost:9090/api/export/<project_id> -o export.sarif
```
