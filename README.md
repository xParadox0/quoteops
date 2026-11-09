# QuoteOps

Quotation and invoice app for machining workshops. Requirements: docs/PRD.md. Design: docs/HLD.md.

## Run it (stage 1)

Needs Docker and Python 3.12. Nothing is published to the host.

Tests (start a throwaway `postgres:16` container on a random loopback port and remove it after; skipped with a message if Docker is unavailable):

```
python3.12 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/python -m pytest -v -rs
```

Stack (compose project `quoteops`, with a `migrate` step that runs before `web`):

```
cp deploy/.env.example deploy/.env      # then replace every placeholder
docker compose -p quoteops -f deploy/compose.yaml up -d --build
docker compose -p quoteops -f deploy/compose.yaml ps
docker compose -p quoteops -f deploy/compose.yaml exec web python -c "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8091/healthz').read())"
docker compose -p quoteops -f deploy/compose.yaml down -v   # -v also deletes the database volume
```

The web container also needs `QO_SECRET` (at least 32 random characters) and `QO_BASE_URL`; it refuses to start without them. Mail: `QO_MAIL=file` (the default) writes each mail as a file into `QO_MAIL_DIR` (a tmpfs in compose), for development and tests. `QO_MAIL=graph` sends through Microsoft Graph and needs `QO_GRAPH_TENANT` and `QO_GRAPH_CLIENT_ID` (GUIDs), `QO_GRAPH_CLIENT_SECRET` and `QO_MAIL_FROM` (the shared mailbox's user principal name); only the web service gets them, and they are set only on the production server (docs/HLD.md section 12). All settings: docs/HLD.md section 9.

Apply the schema by hand (as the owner role, with `QO_DB_HOST`, `QO_OWNER_PASSWORD`, `QO_WEB_PASSWORD`, `QO_ADMIN_PASSWORD` set): `python -m quoteops migrate`.

## Administrator (stage 2b part 2)

The system administrator signs in at a separate service, `admin` in compose (`quoteops.admin_app:app`, port 8092 inside the network, no host port), with email, password and a code from an authenticator app. It connects to the database only as `qo_admin` and needs `QO_ADMIN_PASSWORD`, `QO_ADMIN_SECRET` (at least 32 random characters, not the same as `QO_SECRET`) and `QO_ADMIN_BASE_URL` (its own https address); it refuses to start without them. The web service needs none of these. Details: docs/HLD.md section 11.

Create the administrator, or give an existing one a new password and authenticator secret (this also ends their admin sessions), on the server:

```
docker compose -p quoteops -f deploy/compose.yaml run --rm migrate python -m quoteops create-admin <email>
docker compose -p quoteops -f deploy/compose.yaml run --rm migrate python -m quoteops reset-admin <email>
```

The password is asked twice on the terminal and never taken from the command line. The command prints the authenticator secret and an `otpauth://` URI once: add it to the authenticator app at that moment, it cannot be read back. Without compose, the same commands run as `python -m quoteops create-admin <email>` with `QO_DB_HOST`, `QO_OWNER_USER` and `QO_OWNER_PASSWORD` set.

## Jobs and drawings (stage 3a)

Signed-in users find their company's jobs at `/jobs` ("Quotes"); the owner and estimators create a job with its first drawing (PDF, DXF, PNG or JPG) at `/jobs/new` and add or delete drawings on the job page. Details: docs/HLD.md section 13.

Drawings live on the named volume `qofiles`, mounted only into the `web` service at `/var/qo-files` (`QO_FILES_DIR`), one folder per company with random file names; `admin` and `migrate` never mount it, and every root filesystem stays read-only. The image creates `/var/qo-files` owned by the container user (uid 10001), and Docker gives a new named volume that ownership; a volume created before this stage keeps its old ownership and must be given to uid 10001 by hand, with the web image itself: `docker compose -p quoteops -f deploy/compose.yaml run --rm --no-deps -u 0 web chown 10001:10001 /var/qo-files`. Back the volume up together with the database: they belong together. `docker compose -p quoteops -f deploy/compose.yaml down -v` deletes the files volume as well as the database volume.

Caps (PRD section 6), set in `deploy/.env`: `QO_MAX_FILE_MB` (1 to 200, default 25) per drawing, `QO_MAX_COMPANY_MB` (1 to 100000, default 500) of drawings per company, `QO_MAX_JOBS_PER_MONTH` (1 to 100000, default 50) per calendar month in UTC. One MB is 1048576 bytes. At most four uploads run at once in the web process, one per company; the fifth is the first one answered "busy", after it has waited up to 5 seconds. Temporary files of uploads that never finished are removed when the web service starts.
