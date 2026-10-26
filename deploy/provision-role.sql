-- The identity service's database login, run by deploy.sh as the schema owner after the migrations (which create the
-- identity_app role). Idempotent: creates the login once and resets its password on every run. NOINHERIT: it holds
-- nothing until the service runs SET ROLE identity_app; never a superuser, never BYPASSRLS. The password comes from
-- the environment, never the command line.
\set ON_ERROR_STOP on
\getenv login IDENTITY_DB_USER
\getenv password IDENTITY_DB_PASSWORD

SELECT format('CREATE ROLE %I LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS', :'login')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'login') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD %L',
              :'login', :'password') \gexec
SELECT format('GRANT identity_app TO %I', :'login') \gexec
SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'login') \gexec
