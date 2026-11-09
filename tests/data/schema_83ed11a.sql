-- QuoteOps schema (HLD section 3). Applied as the owner role by `python -m quoteops migrate`.
-- Safe to run repeatedly: every statement is idempotent. No secret lives in this file;
-- role passwords are set by the migrate step from the environment.

CREATE EXTENSION IF NOT EXISTS citext;

-- Roles. The table owner is the migration login and is not defined here.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qo_web') THEN
    CREATE ROLE qo_web LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qo_admin') THEN
    CREATE ROLE qo_admin LOGIN;
  END IF;
END $$;
ALTER ROLE qo_web   LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
ALTER ROLE qo_admin LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;
-- qo_definer owns the lookup functions at the end of this file and nothing else. It cannot log
-- in, and BYPASSRLS lets those functions find a row before any company is known.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qo_definer') THEN
    CREATE ROLE qo_definer NOLOGIN;
  END IF;
END $$;
ALTER ROLE qo_definer NOLOGIN NOSUPERUSER BYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT;

CREATE TABLE IF NOT EXISTS company (
  id          TEXT PRIMARY KEY,            -- 'c_' + random hex, never derived from an email
  name        TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'unverified',  -- unverified | active | suspended | deleting
  tax_label   TEXT, tax_rate NUMERIC(5,2),  -- set by the owner; no default, so no rate is assumed
  quote_next  INT NOT NULL DEFAULT 1,       -- number series per company (F14)
  invoice_next INT NOT NULL DEFAULT 1,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS app_user (
  id UUID PRIMARY KEY, company_id TEXT REFERENCES company(id),  -- NULL only for role 'sysadmin'
  email CITEXT NOT NULL UNIQUE,             -- one account per email, across companies, in v1
  pw_hash BYTEA NOT NULL, pw_salt BYTEA NOT NULL,
  role TEXT NOT NULL CHECK ((role = 'sysadmin') = (company_id IS NULL)),  -- sysadmin | owner | estimator | accountant | viewer
  email_verified_at TIMESTAMPTZ, disabled_at TIMESTAMPTZ,  -- a disabled user keeps history (F5)
  consent_version TEXT NOT NULL, consent_at TIMESTAMPTZ NOT NULL  -- F16
);
CREATE TABLE IF NOT EXISTS session (
  id_hash BYTEA PRIMARY KEY,                -- hash of the cookie value, so a leaked table cannot sign in
  user_id UUID NOT NULL REFERENCES app_user(id), expires_at TIMESTAMPTZ NOT NULL, created_ip INET
);
CREATE TABLE IF NOT EXISTS invite (
  id_hash BYTEA PRIMARY KEY, company_id TEXT NOT NULL, email CITEXT NOT NULL, role TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL, used_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS job (
  id UUID PRIMARY KEY, company_id TEXT NOT NULL, ref TEXT NOT NULL,   -- 'J-1042', unique per company
  customer TEXT NOT NULL, part TEXT NOT NULL, qty INT NOT NULL CHECK (qty > 0),
  material TEXT, due_date DATE, status TEXT NOT NULL,                 -- draft | review | approved | quoted | won | lost | invoiced
  created_by UUID NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS drawing (
  id UUID PRIMARY KEY, company_id TEXT NOT NULL, job_id UUID NOT NULL REFERENCES job(id),
  file_name TEXT NOT NULL, mime TEXT NOT NULL, bytes INT NOT NULL, sha256 BYTEA NOT NULL,
  path TEXT NOT NULL                       -- random, under the company folder; never the user's file name
);
CREATE TABLE IF NOT EXISTS job_value (
  id UUID PRIMARY KEY, company_id TEXT NOT NULL, job_id UUID NOT NULL REFERENCES job(id),
  label TEXT NOT NULL, value TEXT, unit TEXT,
  status TEXT NOT NULL DEFAULT 'to_confirm',  -- to_confirm | confirmed | needs_check | not_found
  source TEXT NOT NULL,                       -- principle 3: 'typed by <user> from callout 4'
  confirmed_by UUID, confirmed_at TIMESTAMPTZ
);
CREATE TABLE IF NOT EXISTS rate (
  id UUID PRIMARY KEY, company_id TEXT NOT NULL, kind TEXT NOT NULL,  -- machine | setup | tooling_pct | margin_pct
  name TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL, valid_from DATE NOT NULL  -- history kept: a quote uses the rate of its date
);
CREATE TABLE IF NOT EXISTS cost_line (
  id UUID PRIMARY KEY, company_id TEXT NOT NULL, job_id UUID NOT NULL,
  label TEXT NOT NULL, hours NUMERIC(8,2), rate_id UUID REFERENCES rate(id),
  amount NUMERIC(14,2) NOT NULL              -- stored, not recomputed later, so an old quote never changes
);
CREATE TABLE IF NOT EXISTS document (
  id UUID PRIMARY KEY, company_id TEXT NOT NULL, job_id UUID NOT NULL,
  kind TEXT NOT NULL,                        -- quotation | invoice
  number TEXT NOT NULL, total NUMERIC(14,2) NOT NULL, issued_at TIMESTAMPTZ, pdf_path TEXT,
  UNIQUE (company_id, kind, number)
);
CREATE TABLE IF NOT EXISTS audit_event (
  id BIGSERIAL PRIMARY KEY, company_id TEXT NOT NULL, actor UUID, at TIMESTAMPTZ NOT NULL DEFAULT now(),
  what TEXT NOT NULL, subject TEXT            -- ids and field names only, never customer text or drawing content
);
CREATE TABLE IF NOT EXISTS support_grant (   -- operator access to a company: needs the company's approval (PRD section 4)
  id UUID PRIMARY KEY, company_id TEXT NOT NULL, granted_by UUID NOT NULL, ends_at TIMESTAMPTZ NOT NULL
);
-- Sign-in, password reset and sign-up throttling (stage 2a). key is sha256(kind|value|secret),
-- computed by the application, so no email or address is stored. Only the qo_throttle_*
-- functions below touch it: forced row-level security, no policy, no grant for qo_web or qo_admin.
CREATE TABLE IF NOT EXISTS auth_throttle (
  key BYTEA NOT NULL, kind TEXT NOT NULL,
  window_start TIMESTAMPTZ NOT NULL, hits INT NOT NULL, blocked_until TIMESTAMPTZ,
  PRIMARY KEY (key, kind)
);

-- Row-level security. ENABLE alone exempts the owner; FORCE removes that exemption.
-- current_setting(..., true) returns NULL when unset, so no company set means no rows
-- (the comparison is NULL, never true) instead of an error.
ALTER TABLE company       ENABLE ROW LEVEL SECURITY;  ALTER TABLE company       FORCE ROW LEVEL SECURITY;
ALTER TABLE app_user      ENABLE ROW LEVEL SECURITY;  ALTER TABLE app_user      FORCE ROW LEVEL SECURITY;
ALTER TABLE session       ENABLE ROW LEVEL SECURITY;  ALTER TABLE session       FORCE ROW LEVEL SECURITY;
ALTER TABLE invite       ENABLE ROW LEVEL SECURITY;  ALTER TABLE invite        FORCE ROW LEVEL SECURITY;
ALTER TABLE job           ENABLE ROW LEVEL SECURITY;  ALTER TABLE job           FORCE ROW LEVEL SECURITY;
ALTER TABLE drawing       ENABLE ROW LEVEL SECURITY;  ALTER TABLE drawing       FORCE ROW LEVEL SECURITY;
ALTER TABLE job_value     ENABLE ROW LEVEL SECURITY;  ALTER TABLE job_value     FORCE ROW LEVEL SECURITY;
ALTER TABLE rate          ENABLE ROW LEVEL SECURITY;  ALTER TABLE rate          FORCE ROW LEVEL SECURITY;
ALTER TABLE cost_line     ENABLE ROW LEVEL SECURITY;  ALTER TABLE cost_line     FORCE ROW LEVEL SECURITY;
ALTER TABLE document      ENABLE ROW LEVEL SECURITY;  ALTER TABLE document      FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_event   ENABLE ROW LEVEL SECURITY;  ALTER TABLE audit_event   FORCE ROW LEVEL SECURITY;
ALTER TABLE support_grant ENABLE ROW LEVEL SECURITY;  ALTER TABLE support_grant FORCE ROW LEVEL SECURITY;
ALTER TABLE auth_throttle ENABLE ROW LEVEL SECURITY;  ALTER TABLE auth_throttle FORCE ROW LEVEL SECURITY;

-- Tenant policy for the web role on every table that carries company_id.
DO $$
DECLARE t TEXT;
BEGIN
  FOREACH t IN ARRAY ARRAY['invite','job','drawing','job_value','rate','cost_line',
                           'document','audit_event','support_grant']
  LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant ON %I', t);
    EXECUTE format(
      'CREATE POLICY tenant ON %I TO qo_web USING (company_id = current_setting(''app.company_id'', true))'
      ' WITH CHECK (company_id = current_setting(''app.company_id'', true))', t);
  END LOOP;
END $$;

-- company: its key is id, not company_id, so the web role matches id against the setting.
DROP POLICY IF EXISTS tenant ON company;
CREATE POLICY tenant ON company TO qo_web
  USING (id = current_setting('app.company_id', true))
  WITH CHECK (id = current_setting('app.company_id', true));
-- company: the admin role lists every company (no content columns live here).
DROP POLICY IF EXISTS admin_read ON company;
CREATE POLICY admin_read ON company FOR SELECT TO qo_admin USING (true);

-- app_user: the web role sees only its own company's users; sysadmin rows (NULL company_id) never match.
DROP POLICY IF EXISTS tenant ON app_user;
CREATE POLICY tenant ON app_user TO qo_web
  USING (company_id = current_setting('app.company_id', true))
  WITH CHECK (company_id = current_setting('app.company_id', true));
-- app_user: the admin role reads all users, including sysadmins, to manage accounts; read only.
-- Its grant is column-level (see Privileges), so pw_hash and pw_salt stay out of its reach.
DROP POLICY IF EXISTS admin_read ON app_user;
CREATE POLICY admin_read ON app_user FOR SELECT TO qo_admin USING (true);

-- session: deliberately no policy and no grant for qo_web or qo_admin. A session row has no
-- company_id, and a cookie is looked up before any company is known, so only the qo_session_*
-- functions below touch this table.

-- audit_event: the admin role reads the trail of every company (ids and field names only by design).
DROP POLICY IF EXISTS admin_read ON audit_event;
CREATE POLICY admin_read ON audit_event FOR SELECT TO qo_admin USING (true);
-- support_grant: the admin role must see which grants are active before it may look inside a company.
DROP POLICY IF EXISTS admin_read ON support_grant;
CREATE POLICY admin_read ON support_grant FOR SELECT TO qo_admin USING (true);

-- Counts per company for the administrator pages. No content columns. The view runs with its
-- owner's rights, so qo_admin needs no grant on the underlying content tables.
CREATE OR REPLACE VIEW company_usage AS
SELECT c.id AS company_id, c.status, c.created_at,
       (SELECT count(*) FROM app_user u WHERE u.company_id = c.id)::int AS users,
       (SELECT count(*) FROM job j WHERE j.company_id = c.id)::int AS jobs,
       (SELECT count(*) FROM drawing d WHERE d.company_id = c.id)::int AS drawings,
       (SELECT count(*) FROM document x WHERE x.company_id = c.id)::int AS documents,
       (SELECT count(*) FROM audit_event a WHERE a.company_id = c.id)::int AS audit_events
FROM company c;

-- Privileges. Start from nothing, then grant.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM qo_web, qo_admin, qo_definer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM qo_web, qo_admin, qo_definer;
GRANT USAGE ON SCHEMA public TO qo_web, qo_admin, qo_definer;

GRANT SELECT, INSERT, UPDATE, DELETE ON
  company, app_user, invite, job, drawing, job_value, rate, cost_line, document,
  audit_event, support_grant TO qo_web;
GRANT USAGE ON SEQUENCE audit_event_id_seq TO qo_web;

GRANT SELECT ON company, audit_event, support_grant, company_usage TO qo_admin;
GRANT SELECT (id, company_id, email, role, email_verified_at, disabled_at, consent_version, consent_at)
  ON app_user TO qo_admin;

-- qo_definer: exactly the columns the functions below read, and the session writes they make.
GRANT SELECT (id, company_id, email, pw_hash, pw_salt, role, email_verified_at, disabled_at)
  ON app_user TO qo_definer;
GRANT SELECT (id_hash, user_id, expires_at) ON session TO qo_definer;
GRANT INSERT, DELETE ON session TO qo_definer;
GRANT SELECT (id_hash, company_id, email, role, expires_at, used_at) ON invite TO qo_definer;
GRANT SELECT (id, status, created_at) ON company TO qo_definer;
-- qo_purge_unverified deletes unverified companies and their never-verified owners (owner
-- decision 2026-11-08). DELETE has no column-level form, so it is table level; the function
-- itself never touches a company that is not 'unverified' or a user with email_verified_at set.
GRANT DELETE ON company, app_user TO qo_definer;
-- qo_throttle_check upserts with RETURNING and both throttle functions prune old rows.
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_throttle TO qo_definer;

-- No temporary tables for the application roles: a temporary table is searched before public
-- unless pg_temp is named, so it could shadow a table. The functions below also name pg_temp
-- last and qualify every table. The database name is the deployment's, hence current_database().
-- The migration login must be a superuser or the database owner, or this revoke has no effect.
DO $$
BEGIN
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, qo_web, qo_admin', current_database());
END $$;

-- Lookups that run before a company is known. Each is SECURITY DEFINER as qo_definer, pins
-- search_path so a caller cannot substitute an object, and is callable by qo_web only.

-- Sign-in: find one account by email. It necessarily returns pw_hash and pw_salt to the web
-- role, because scrypt cannot run in PostgreSQL; this is bounded to one row per call (email is
-- unique), there is no way to list users, and the application rate-limits sign-in (HLD 4).
-- company_status lets the application refuse a suspended or deleting company; it is NULL for a
-- sysadmin. A database migrated before company_status existed holds the old output columns,
-- which CREATE OR REPLACE cannot change, so that version is dropped first; the owner and grants
-- are set again below.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_catalog.pg_proc
             WHERE oid = pg_catalog.to_regprocedure('public.qo_login_lookup(citext)')
               AND NOT ('company_status' = ANY (proargnames))) THEN
    DROP FUNCTION public.qo_login_lookup(citext);
  END IF;
END $$;
CREATE OR REPLACE FUNCTION qo_login_lookup(p_email citext)
RETURNS TABLE (id uuid, company_id text, pw_hash bytea, pw_salt bytea, role text,
               email_verified_at timestamptz, disabled_at timestamptz, company_status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT u.id, u.company_id, u.pw_hash, u.pw_salt, u.role, u.email_verified_at, u.disabled_at,
         c.status
  FROM public.app_user u LEFT JOIN public.company c ON c.id = u.company_id
  WHERE u.email = p_email LIMIT 1
$$;

-- Sign-in success: store the hash of the new cookie; qo_web has no grant on session.
CREATE OR REPLACE FUNCTION qo_session_create(p_id_hash bytea, p_user_id uuid,
                                             p_expires_at timestamptz, p_ip inet)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  INSERT INTO public.session (id_hash, user_id, expires_at, created_ip)
  VALUES (p_id_hash, p_user_id, p_expires_at, p_ip)
$$;

-- Each request: resolve the cookie hash to a user and company; expired, disabled, or a
-- suspended or deleting company is no row. A sysadmin has no company and is not affected; any
-- other user whose company row is missing gets no row (c.status is NULL, NOT IN is not true).
CREATE OR REPLACE FUNCTION qo_session_lookup(p_id_hash bytea)
RETURNS TABLE (user_id uuid, company_id text, role text, expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT s.user_id, u.company_id, u.role, s.expires_at
  FROM public.session s JOIN public.app_user u ON u.id = s.user_id
       LEFT JOIN public.company c ON c.id = u.company_id
  WHERE s.id_hash = p_id_hash AND s.expires_at > now() AND u.disabled_at IS NULL
    AND ((u.company_id IS NULL AND u.role = 'sysadmin')
         OR c.status NOT IN ('suspended', 'deleting'))
  LIMIT 1
$$;

-- Sign-out: remove one session by its hash.
CREATE OR REPLACE FUNCTION qo_session_delete(p_id_hash bytea)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  DELETE FROM public.session WHERE id_hash = p_id_hash
$$;

-- Invite link: resolve the token hash to its company before the invitee has one; used or
-- expired is no row.
CREATE OR REPLACE FUNCTION qo_invite_lookup(p_id_hash bytea)
RETURNS TABLE (company_id text, email citext, role text, expires_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT i.company_id, i.email, i.role, i.expires_at
  FROM public.invite i
  WHERE i.id_hash = p_id_hash AND i.used_at IS NULL AND i.expires_at > now()
  LIMIT 1
$$;

ALTER FUNCTION qo_login_lookup(citext) OWNER TO qo_definer;
ALTER FUNCTION qo_session_create(bytea, uuid, timestamptz, inet) OWNER TO qo_definer;
ALTER FUNCTION qo_session_lookup(bytea) OWNER TO qo_definer;
ALTER FUNCTION qo_session_delete(bytea) OWNER TO qo_definer;
ALTER FUNCTION qo_invite_lookup(bytea) OWNER TO qo_definer;
REVOKE ALL ON FUNCTION qo_login_lookup(citext), qo_session_create(bytea, uuid, timestamptz, inet),
  qo_session_lookup(bytea), qo_session_delete(bytea), qo_invite_lookup(bytea)
  FROM PUBLIC, qo_admin;
GRANT EXECUTE ON FUNCTION qo_login_lookup(citext), qo_session_create(bytea, uuid, timestamptz, inet),
  qo_session_lookup(bytea), qo_session_delete(bytea), qo_invite_lookup(bytea)
  TO qo_web;

-- Stage 2a. Same pattern as above: SECURITY DEFINER as qo_definer, pinned search_path, every
-- table qualified, callable by qo_web only.

-- Throttle: count one hit for (key, kind) and say whether the caller may go on. More than
-- p_limit hits inside p_window_seconds blocks the key for p_block_seconds; a block is not
-- extended by further hits. After a block or a window ends, counting starts again at one.
-- Rows older than a day that are not blocked are deleted on the way.
CREATE OR REPLACE FUNCTION qo_throttle_check(p_key bytea, p_kind text, p_limit int,
                                             p_window_seconds int, p_block_seconds int)
RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  DELETE FROM public.auth_throttle
  WHERE window_start < now() - interval '1 day'
    AND (blocked_until IS NULL OR blocked_until < now());
  INSERT INTO public.auth_throttle AS t (key, kind, window_start, hits, blocked_until)
  VALUES (p_key, p_kind, now(), 1,
          CASE WHEN 1 > p_limit THEN now() + make_interval(secs => p_block_seconds) END)
  ON CONFLICT (key, kind) DO UPDATE SET
    window_start = CASE WHEN (t.blocked_until IS NOT NULL AND t.blocked_until <= now())
                          OR (t.blocked_until IS NULL
                              AND t.window_start <= now() - make_interval(secs => p_window_seconds))
                        THEN now() ELSE t.window_start END,
    hits = CASE WHEN (t.blocked_until IS NOT NULL AND t.blocked_until <= now())
                  OR (t.blocked_until IS NULL
                      AND t.window_start <= now() - make_interval(secs => p_window_seconds))
                THEN 1 ELSE t.hits + 1 END,
    blocked_until = CASE
      WHEN t.blocked_until > now() THEN t.blocked_until
      WHEN (t.blocked_until IS NOT NULL AND t.blocked_until <= now())
        OR (t.blocked_until IS NULL
            AND t.window_start <= now() - make_interval(secs => p_window_seconds))
        THEN CASE WHEN 1 > p_limit THEN now() + make_interval(secs => p_block_seconds) END
      WHEN t.hits + 1 > p_limit THEN now() + make_interval(secs => p_block_seconds)
    END
  RETURNING blocked_until IS NULL OR blocked_until <= now()
$$;

-- Successful sign-in: forget the failures counted for that key.
CREATE OR REPLACE FUNCTION qo_throttle_reset(p_key bytea, p_kind text)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  DELETE FROM public.auth_throttle
  WHERE (key = p_key AND kind = p_kind)
     OR (window_start < now() - interval '1 day'
         AND (blocked_until IS NULL OR blocked_until < now()))
$$;

-- Sign-up cap: the verified companies (active, suspended or deleting), which the web role
-- cannot see past row-level security. An unverified company does not count; it is purged below.
CREATE OR REPLACE FUNCTION qo_company_count()
RETURNS int
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  SELECT count(*)::int FROM public.company WHERE status IN ('active', 'suspended', 'deleting')
$$;

-- Password reset: end every session of one user.
CREATE OR REPLACE FUNCTION qo_session_delete_user(p_user_id uuid)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  DELETE FROM public.session WHERE user_id = p_user_id
$$;

-- Abandoned sign-ups: delete unverified companies, their owners and (defensively) their
-- sessions, and return how many companies went. A company is doomed when its status is
-- 'unverified', none of its users has email_verified_at, and it is older than
-- p_older_than_seconds or not among the p_keep newest companies with status 'unverified'.
-- At most 500 companies per call, the oldest first. The application calls it under the same
-- advisory lock as verification, so no account is verified while it runs; as a backstop the
-- DELETEs repeat the status and email_verified_at conditions, which PostgreSQL re-checks on a
-- row changed meanwhile, and a company that keeps a user cannot be deleted (foreign key).
-- Data-modifying CTEs all run; the foreign keys are checked at the end of the statement.
CREATE OR REPLACE FUNCTION qo_purge_unverified(p_older_than_seconds int, p_keep int)
RETURNS int
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, public, pg_temp AS $$
  WITH ranked AS (
    SELECT c.id, c.created_at,
           row_number() OVER (ORDER BY c.created_at DESC, c.id DESC) AS newest
    FROM public.company c
    WHERE c.status = 'unverified'
  ), doomed AS (
    SELECT r.id FROM ranked r
    WHERE (r.created_at < now() - make_interval(secs => p_older_than_seconds) OR r.newest > p_keep)
      AND NOT EXISTS (SELECT 1 FROM public.app_user v
                      WHERE v.company_id = r.id AND v.email_verified_at IS NOT NULL)
    ORDER BY r.created_at, r.id
    LIMIT 500
  ), gone_sessions AS (
    DELETE FROM public.session s USING public.app_user u, doomed d
    WHERE s.user_id = u.id AND u.company_id = d.id
    RETURNING s.user_id
  ), gone_users AS (
    DELETE FROM public.app_user u USING doomed d
    WHERE u.company_id = d.id AND u.email_verified_at IS NULL
    RETURNING u.id
  ), gone_companies AS (
    DELETE FROM public.company c USING doomed d
    WHERE c.id = d.id AND c.status = 'unverified'
    RETURNING c.id
  )
  SELECT count(*)::int FROM gone_companies
$$;

ALTER FUNCTION qo_throttle_check(bytea, text, int, int, int) OWNER TO qo_definer;
ALTER FUNCTION qo_throttle_reset(bytea, text) OWNER TO qo_definer;
ALTER FUNCTION qo_company_count() OWNER TO qo_definer;
ALTER FUNCTION qo_session_delete_user(uuid) OWNER TO qo_definer;
ALTER FUNCTION qo_purge_unverified(int, int) OWNER TO qo_definer;
REVOKE ALL ON FUNCTION qo_throttle_check(bytea, text, int, int, int), qo_throttle_reset(bytea, text),
  qo_company_count(), qo_session_delete_user(uuid), qo_purge_unverified(int, int)
  FROM PUBLIC, qo_admin;
GRANT EXECUTE ON FUNCTION qo_throttle_check(bytea, text, int, int, int), qo_throttle_reset(bytea, text),
  qo_company_count(), qo_session_delete_user(uuid), qo_purge_unverified(int, int)
  TO qo_web;
