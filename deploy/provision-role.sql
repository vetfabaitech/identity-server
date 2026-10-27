-- The identity service's database login, run by deploy.sh as the schema owner after the migrations (which create the
-- identity_app role). Idempotent: creates the login once and resets its password on every run. NOINHERIT: it holds
-- nothing until the service runs SET ROLE identity_app; never a superuser, never BYPASSRLS. The password comes from
-- the environment, never the command line.
\set ON_ERROR_STOP on
\getenv login IDENTITY_DB_USER
\getenv password IDENTITY_DB_PASSWORD

-- The attributes are set when the login is CREATED. They are not restated afterwards: on a managed Postgres (Supabase)
-- the owner is not a superuser and may not mention SUPERUSER/BYPASSRLS even to turn them off. An existing login
-- therefore keeps its attributes, and the check below refuses to continue if any of them is a privilege this service
-- must never hold. Only the password, LOGIN and NOINHERIT are (re)set, so a re-run rotates the password.
SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L',
              :'login', :'password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'login') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN NOINHERIT PASSWORD %L', :'login', :'password') \gexec
SELECT 'DO $guard$ BEGIN RAISE EXCEPTION ''the service login must not be a superuser, create roles or databases, or bypass row-level security''; END $guard$'
 FROM pg_roles
WHERE rolname = :'login' AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb) \gexec
SELECT format('GRANT identity_app TO %I', :'login') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'login') \gexec
