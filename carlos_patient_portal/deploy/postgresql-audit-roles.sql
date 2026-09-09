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
  session_user = current_user
  AND current_user NOT IN (:'owner_role', :'runtime_role', :'maintenance_role')
  AND :'runtime_role' <> :'maintenance_role'
  AND :'runtime_role' <> :'owner_role'
  AND :'maintenance_role' <> :'owner_role'
  AND (
    SELECT rolcanlogin
      AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
    FROM pg_roles
    WHERE rolname = current_user
  ) IS TRUE
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
  AND NOT EXISTS (
    SELECT 1
    FROM pg_auth_members membership
    JOIN pg_roles member_role ON member_role.oid = membership.member
    JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
    WHERE granted_role.rolname IN (
      current_user,
      :'owner_role',
      :'runtime_role',
      :'maintenance_role'
    )
      AND NOT (
        granted_role.rolname = :'owner_role'
        AND member_role.rolname = current_user
      )
  )
  AND (
    SELECT database_owner.rolname = current_user
    FROM pg_database database_record
    JOIN pg_roles database_owner ON database_owner.oid = database_record.datdba
    WHERE database_record.datname = current_database()
  ) IS TRUE
  AND EXISTS (
    SELECT 1
    FROM pg_auth_members membership
    JOIN pg_roles member_role ON member_role.oid = membership.member
    JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
    WHERE member_role.rolname = current_user
      AND granted_role.rolname = :'owner_role'
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_auth_members membership
    JOIN pg_roles member_role ON member_role.oid = membership.member
    JOIN pg_roles granted_role ON granted_role.oid = membership.roleid
    WHERE member_role.rolname = current_user
      AND granted_role.rolname <> :'owner_role'
  )
    AS role_attributes_valid
\gset
\if :role_attributes_valid
\else
  \echo 'Database admin must connect directly, own the database, be a direct member only of the schema-owner role, and not be inherited by another role. Schema-owner, runtime, and maintenance must be distinct LOGIN roles without elevated attributes or memberships; only the database admin may inherit the schema owner.'
  -- psql 16 has no nonzero \quit argument. ON_ERROR_STOP turns this deliberate SQL error into a
  -- failing process status that the deployment command cannot mistake for success.
  SELECT 1 / 0 AS database_role_policy_violation;
\endif

BEGIN;

-- A fixed search_path does not suppress PostgreSQL's implicit pg_temp precedence. The application
-- never needs temporary objects, so remove the database privilege that could create a shadow table.
SELECT format(
  'REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC, %I, %I;',
  current_database(),
  :'runtime_role',
  :'maintenance_role'
)
\gexec

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
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"runtime_role" CASCADE;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"runtime_role" CASCADE;
-- Also generate explicit column revocations for every base/partitioned table so the intended ACL
-- reset remains visible and a stale narrow grant cannot bypass the table privilege allowlist.
SELECT format(
  'REVOKE SELECT (%1$s), INSERT (%1$s), UPDATE (%1$s), REFERENCES (%1$s) ON TABLE %2$I.%3$I FROM %4$I, %5$I, PUBLIC CASCADE;',
  string_agg(quote_ident(attribute_record.attname), ', ' ORDER BY attribute_record.attnum),
  namespace_record.nspname,
  relation_record.relname,
  :'runtime_role',
  :'maintenance_role'
)
FROM pg_class relation_record
JOIN pg_namespace namespace_record ON namespace_record.oid = relation_record.relnamespace
JOIN pg_attribute attribute_record ON attribute_record.attrelid = relation_record.oid
WHERE namespace_record.nspname = 'public'
  AND relation_record.relkind IN ('r', 'p')
  AND attribute_record.attnum > 0
  AND NOT attribute_record.attisdropped
GROUP BY namespace_record.nspname, relation_record.relname
\gexec
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
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM :"maintenance_role" CASCADE;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM :"maintenance_role" CASCADE;
GRANT SELECT, DELETE ON public.patient_portal_audit_events TO :"maintenance_role";

-- Apply grants only when neither restricted role can bypass them through database/schema creation
-- or ownership. Check after moving the audit table so the final state is what gets approved.
SELECT
  NOT has_database_privilege(:'owner_role', current_database(), 'CREATE')
  AND NOT has_database_privilege(:'runtime_role', current_database(), 'CREATE')
  AND NOT has_database_privilege(:'maintenance_role', current_database(), 'CREATE')
  AND NOT has_database_privilege(:'runtime_role', current_database(), 'TEMPORARY')
  AND NOT has_database_privilege(:'maintenance_role', current_database(), 'TEMPORARY')
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
  AND NOT EXISTS (
    SELECT 1
    FROM pg_namespace namespace_record
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND (
        has_schema_privilege(:'runtime_role', namespace_record.oid, 'CREATE')
        OR has_schema_privilege(:'maintenance_role', namespace_record.oid, 'CREATE')
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_namespace namespace_record
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND namespace_record.nspname <> 'public'
      AND (
        has_schema_privilege(:'runtime_role', namespace_record.oid, 'USAGE')
        OR has_schema_privilege(:'maintenance_role', namespace_record.oid, 'USAGE')
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = relation_record.relnamespace
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND namespace_record.nspname <> 'public'
      AND relation_record.relkind IN ('r', 'p', 'v', 'm', 'f')
      AND (
        has_table_privilege(
          :'runtime_role',
          relation_record.oid,
          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
        OR has_table_privilege(
          :'maintenance_role',
          relation_record.oid,
          'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
        )
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class sequence_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = sequence_record.relnamespace
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND namespace_record.nspname <> 'public'
      AND sequence_record.relkind = 'S'
      AND (
        has_sequence_privilege(
          :'runtime_role', sequence_record.oid, 'USAGE,SELECT,UPDATE'
        )
        OR has_sequence_privilege(
          :'maintenance_role', sequence_record.oid, 'USAGE,SELECT,UPDATE'
        )
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_proc function_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = function_record.pronamespace
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND namespace_record.nspname <> 'public'
      AND (
        has_function_privilege(:'runtime_role', function_record.oid, 'EXECUTE')
        OR has_function_privilege(:'maintenance_role', function_record.oid, 'EXECUTE')
      )
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_namespace namespace_record
    JOIN pg_roles owner_role_record ON owner_role_record.oid = namespace_record.nspowner
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_class relation_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = relation_record.relnamespace
    JOIN pg_roles owner_role_record ON owner_role_record.oid = relation_record.relowner
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_proc function_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = function_record.pronamespace
    JOIN pg_roles owner_role_record ON owner_role_record.oid = function_record.proowner
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pg_type type_record
    JOIN pg_namespace namespace_record ON namespace_record.oid = type_record.typnamespace
    JOIN pg_roles owner_role_record ON owner_role_record.oid = type_record.typowner
    WHERE namespace_record.nspname <> 'information_schema'
      AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      AND owner_role_record.rolname IN (:'runtime_role', :'maintenance_role')
  )
  AND NOT EXISTS (
    SELECT 1
    FROM (
      SELECT acl.grantee, namespace_record.nspowner AS owner_oid
      FROM pg_namespace namespace_record
      CROSS JOIN LATERAL aclexplode(namespace_record.nspacl) acl
      WHERE namespace_record.nspname <> 'information_schema'
        AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      UNION ALL
      SELECT acl.grantee, relation_record.relowner AS owner_oid
      FROM pg_class relation_record
      JOIN pg_namespace namespace_record ON namespace_record.oid = relation_record.relnamespace
      CROSS JOIN LATERAL aclexplode(relation_record.relacl) acl
      WHERE namespace_record.nspname <> 'information_schema'
        AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      UNION ALL
      SELECT acl.grantee, relation_record.relowner AS owner_oid
      FROM pg_attribute attribute_record
      JOIN pg_class relation_record ON relation_record.oid = attribute_record.attrelid
      JOIN pg_namespace namespace_record ON namespace_record.oid = relation_record.relnamespace
      CROSS JOIN LATERAL aclexplode(attribute_record.attacl) acl
      WHERE namespace_record.nspname <> 'information_schema'
        AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
        AND attribute_record.attnum > 0
        AND NOT attribute_record.attisdropped
      UNION ALL
      SELECT acl.grantee, function_record.proowner AS owner_oid
      FROM pg_proc function_record
      JOIN pg_namespace namespace_record ON namespace_record.oid = function_record.pronamespace
      CROSS JOIN LATERAL aclexplode(function_record.proacl) acl
      WHERE namespace_record.nspname <> 'information_schema'
        AND namespace_record.nspname NOT LIKE 'pg\_%' ESCAPE '\'
      UNION ALL
      SELECT acl.grantee, default_acl.defaclrole AS owner_oid
      FROM pg_default_acl default_acl
      CROSS JOIN LATERAL aclexplode(default_acl.defaclacl) acl
      WHERE default_acl.defaclrole = (
        SELECT oid FROM pg_roles WHERE rolname = :'owner_role'
      )
    ) unexpected_acl
    WHERE unexpected_acl.grantee <> unexpected_acl.owner_oid
      AND unexpected_acl.grantee NOT IN (
        SELECT oid
        FROM pg_roles
        WHERE rolname IN (
          current_user,
          :'owner_role',
          :'runtime_role',
          :'maintenance_role'
        )
      )
  ) AS role_ownership_valid
\gset
\if :role_ownership_valid
\else
  \echo 'Runtime and maintenance roles must not own non-system-schema objects, create database/schema/temporary objects, or hold privileges outside public; the schema owner must not own or create databases, and user-schema ACLs must not grant access to undeclared roles.'
  SELECT 1 / 0 AS database_role_policy_violation;
\endif

COMMIT;
