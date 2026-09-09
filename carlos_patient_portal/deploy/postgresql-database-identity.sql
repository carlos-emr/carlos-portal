\set ON_ERROR_STOP on

-- A database name alone is not an identity: separate PostgreSQL clusters commonly use the same
-- name and OID. The control-system identifier binds the comparison to one physical cluster while
-- remaining safe to print in deployment logs.
SELECT concat_ws(
  '|',
  encode(convert_to(control_record.system_identifier::text, 'UTF8'), 'hex'),
  encode(convert_to(database_record.oid::text, 'UTF8'), 'hex'),
  encode(convert_to(current_database(), 'UTF8'), 'hex'),
  CASE WHEN session_user = current_user THEN 'direct' ELSE 'switched' END
)
FROM pg_control_system() control_record
JOIN pg_database database_record ON database_record.datname = current_database();
