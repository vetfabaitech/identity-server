-- LOCAL DEVELOPMENT ONLY.
--
-- In shared environments `public.users` belongs to the identity service
-- (vetfab-main/log-in/backend/supabase_migration_users.sql and
-- supabase_migration_beta_access.sql). The LMS API never writes it; it reads
-- the signed-in user's status through lms.current_identity() (ADR-0001).
-- This stub reproduces only the columns that function reads, so the LMS can
-- run against a local Postgres without the identity service's schema.
create extension if not exists pgcrypto;

create table if not exists public.users (
  id uuid primary key default gen_random_uuid(),
  email text not null unique,
  display_name text not null,
  status text not null default 'pending'
    check (status in ('pending', 'approved', 'rejected', 'suspended')),
  role text not null default 'beta_user' check (role in ('admin', 'beta_user')),
  created_at timestamptz not null default now()
);

-- Same deny-by-default posture as the identity service's table (no policies:
-- only the owner and definer functions read it).
alter table public.users enable row level security;
