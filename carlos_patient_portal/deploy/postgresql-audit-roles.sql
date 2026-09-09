-- Apply after migrations with psql variables naming pre-created LOGIN roles:
--   psql "$DATABASE_ADMIN_URL" \
--     -v owner_role=portal_schema_owner \
--     -v runtime_role=portal_runtime \
--     -v maintenance_role=portal_audit_maintenance \
--     -f postgresql-audit-roles.sql
-- The deployment platform owns role creation/password delivery. The web and outbox processes use
-- runtime_role; only the offline prune job receives maintenance_role credentials.

\set ON_ERROR_STOP on

-- These credentials are deliberately narrow. REVOKE cannot neutralize ownership, administrator
-- attributes, or inherited privileges, so reject such roles before changing any grants.
SELECT
  current_user NOT IN (:'owner_role', :'runtime_role', :'maintenance_role')
  AND :'runtime_role' <> :'maintenance_role'
  AND :'runtime_role' <> :'owner_role'
  AND :'maintenance_role' <> :'owner_role'
  AND (
    SELECT rolcanlogin
      AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    FROM pg_roles
    WHERE rolname = :'owner_role'
  ) IS TRUE
  AND (
    SELECT rolcanlogin
      AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    FROM pg_roles
    WHERE rolname = :'runtime_role'
  ) IS TRUE
  AND (
    SELECT rolcanlogin
      AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    FROM pg_roles
    WHERE rolname = :'maintenance_role'
  ) IS TRUE
  AND NOT EXISTS (
    SELECT 1
    FROM pg_auth_members membership
    JOIN pg_roles member_role ON member_role.oid = membership.member
    WHERE member_role.rolname IN (:'owner_role', :'runtime_role', :'maintenance_role')
  )
  AND (
    SELECT database_owner.rolname = current_user
    FROM pg_database database_record
    JOIN pg_roles database_owner ON database_owner.oid = database_record.datdba
    WHERE database_record.datname = current_database()
  ) IS TRUE
  AND pg_has_role(current_user, :'owner_role', 'MEMBER')
    AS role_attributes_valid
\gset
\if :role_attributes_valid
\else
  \echo 'Database admin must own the database and be a member of the schema-owner role; schema-owner, runtime, and maintenance must be distinct LOGIN roles without elevated attributes or memberships.'
  -- psql 16 has no nonzero \quit argument. ON_ERROR_STOP turns this deliberate SQL error into a
  -- failing process status that the deployment command cannot mistake for success.
  SELECT 1 / 0 AS database_role_policy_violation;
\endif

BEGIN;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO :"runtime_role", :"maintenance_role";
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM :"runtime_role", :"maintenance_role";
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_role" IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_role" IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE :"owner_role" IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- The runtime role needs ordinary application DML but must not own the evidence table. Run this
-- after every migration, or mirror these grants through deployment-managed default privileges.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"runtime_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"runtime_role";
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.patient_portal_accounts,
  public.patient_portal_audit_events,
  public.patient_portal_contact_review_requests,
  public.patient_portal_email_change_requests,
  public.patient_portal_invites,
  public.patient_portal_mfa_challenges,
  public.patient_portal_outbound_deliveries,
  public.patient_portal_password_reset_tokens,
  public.patient_portal_sessions,
  public.patient_portal_unlock_secrets
TO :"runtime_role";
GRANT USAGE, SELECT ON SEQUENCE
  public.patient_portal_accounts_id_seq,
  public.patient_portal_audit_events_id_seq,
  public.patient_portal_contact_review_requests_id_seq,
  public.patient_portal_email_change_requests_id_seq,
  public.patient_portal_invites_id_seq,
  public.patient_portal_mfa_challenges_id_seq,
  public.patient_portal_outbound_deliveries_id_seq,
  public.patient_portal_password_reset_tokens_id_seq,
  public.patient_portal_sessions_id_seq,
  public.patient_portal_unlock_secrets_id_seq
TO :"runtime_role";

-- Schema state is migration evidence. The application reads it for readiness but must never be
-- able to claim a different migration head or erase the only recorded head.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON public.alembic_version FROM :"runtime_role";
GRANT SELECT ON public.alembic_version TO :"runtime_role";

ALTER TABLE public.patient_portal_audit_events OWNER TO :"owner_role";
REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
  ON public.patient_portal_audit_events FROM :"runtime_role";
GRANT SELECT, INSERT ON public.patient_portal_audit_events TO :"runtime_role";

-- Pruning is deliberately isolated. This role cannot modify application state or insert evidence.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"maintenance_role";
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"maintenance_role";
GRANT SELECT, DELETE ON public.patient_portal_audit_events TO :"maintenance_role";

-- Apply grants only when neither restricted role can bypass them through database/schema creation
-- or ownership. Check after moving the audit table so the final state is what gets approved.
SELECT
  NOT has_database_privilege(:'owner_role', current_database(), 'CREATE')
  AND NOT has_database_privilege(:'runtime_role', current_database(), 'CREATE')
  AND NOT has_database_privilege(:'maintenance_role', current_database(), 'CREATE')
  AND NOT EXISTS (
    SELECT 1
    FROM pg_database database_record
    JOIN pg_roles owner_role_record ON owner_role_record.oid = database_record.datdba
    WHERE database_record.datname = current_database()
      AND owner_role_record.rolname IN (
        :'owner_role',
        :'runtime_role',
        :'maintenance_role'
      )
  )
  AND NOT has_schema_privilege(:'runtime_role', 'public', 'CREATE')
  AND NOT has_schema_privilege(:'maintenance_role', 'public', 'CREATE')
  AND NOT EXISTS (
    SELECT 1
    FROM pg_namespace namespace_record
    JOIN pg_roles owner_role_record ON owner_role_record.oid = namespace_record.nspowner
    WHERE namespace_record.nspname = 'public'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = relation_record.relnamespace
    JOIN pg_roles owner_role_record ON owner_role_record.oid = relation_record.relowner
    WHERE namespace_record.nspname = 'public'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_proc function_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = function_record.pronamespace
    JOIN pg_roles owner_role_record ON owner_role_record.oid = function_record.proowner
    WHERE namespace_record.nspname = 'public'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_type type_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = type_record.typnamespace
    JOIN pg_roles owner_role_record ON owner_role_record.oid = type_record.typowner
    WHERE namespace_record.nspname = 'public'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  ) AS role_ownership_valid
\gset
\if :role_ownership_valid
\else
  \echo 'Runtime and maintenance roles must not own public-schema objects or create database/schema objects; the schema owner must not own or create databases.'
  SELECT 1 / 0 AS database_role_policy_violation;
\endif

COMMIT;
