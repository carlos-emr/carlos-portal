# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Frozen physical identities of the two histories consumed by revision 0019.

No current application models are imported: later model changes must not change an
earlier migration. The readable historical catalogs are retained in the regression
fixture; only their canonical per-table hashes are needed in the installed package.
"""

import hashlib
import json
import re
from typing import Any

import sqlalchemy as sa
from sqlalchemy.engine import Connection

_AUDIT_TABLE = "patient_portal_audit_events"
_AUDIT_CHECK = "ck_patient_portal_audit_events_event_type"
_TOKENS = re.compile(
    r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|[a-zA-Z_][a-zA-Z_0-9$]*|::|<=|>=|<>|!=|.", re.S
)


def _sql(value: str, schema: str | None) -> list[str]:
    tokens = []
    for token in _TOKENS.findall(value):
        if token.isspace():
            continue
        if token.startswith("'"):
            tokens.append(token)
        elif token.startswith('"'):
            name = token[1:-1].replace('""', '"')
            tokens.append(name if re.fullmatch(r"[a-z_][a-z_0-9$]*", name) else token)
        else:
            tokens.append(token.lower())
    # References to the same physical namespace may be qualified or search-path visible.
    # Keep other namespaces intact: a foreign-schema FK/default is a different identity.
    result = []
    index = 0
    while index < len(tokens):
        identifier = tokens[index].strip('"')
        if schema is not None and identifier == schema and tokens[index + 1 : index + 2] == ["."]:
            index += 2
        else:
            result.append(tokens[index])
            index += 1
    return result


def _ordered(values: list[Any]) -> list[Any]:
    return sorted(
        values, key=lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    )


def _json_value(value: object, schema: str) -> object:
    if isinstance(value, dict):
        return {key: _json_value(item, schema) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_value(item, schema) for item in value]
    if isinstance(value, sa.sql.ClauseElement):
        return _sql(str(value), schema)
    return value


def _namespace(connection: Connection) -> str:
    if connection.dialect.name == "sqlite":
        return "main"
    schema = connection.scalar(
        sa.text(
            "SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE c.oid=to_regclass('alembic_version')"
        )
    )
    if not isinstance(schema, str):
        raise RuntimeError("migration 0019 cannot locate its version-table namespace")
    return schema


def _qualified(connection: Connection, schema: str, name: str) -> str:
    quote = connection.dialect.identifier_preparer.quote
    return quote(schema) + "." + quote(name)


def _sequence(connection: Connection, value: str, table: str, schema: str) -> dict[str, Any]:
    row = (
        connection.execute(
            sa.text(
                "SELECT n.nspname,c.relname,c.relowner=t.relowner AS owner_matches_table, "
                "s.seqtypid::regtype::text AS type,s.seqstart,s.seqincrement,s.seqmax,s.seqmin, "
                "s.seqcache,s.seqcycle FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
                "JOIN pg_sequence s ON s.seqrelid=c.oid CROSS JOIN pg_class t "
                "WHERE c.oid=to_regclass(:sequence) AND t.oid=to_regclass(:table)"
            ),
            {"sequence": value, "table": _qualified(connection, schema, table)},
        )
        .mappings()
        .one()
    )
    return {
        "schema": None if row["nspname"] == schema else row["nspname"],
        "name": row["relname"],
        "owner_matches_table": row["owner_matches_table"],
        "parameters": [
            row[key]
            for key in (
                "type",
                "seqstart",
                "seqincrement",
                "seqmax",
                "seqmin",
                "seqcache",
                "seqcycle",
            )
        ],
    }


def _default(connection: Connection, value: str | None, table: str, schema: str) -> object:
    if value is None:
        return None
    if connection.dialect.name == "postgresql":
        match = re.fullmatch(r"nextval\('((?:''|[^'])+)'::regclass\)", value)
        if match:
            return {"nextval": _sequence(connection, match[1].replace("''", "'"), table, schema)}
    return {"sql": _sql(value, schema)}


def _postgresql_table(connection: Connection, table: str, schema: str) -> dict[str, Any]:
    parameters = {"table": _qualified(connection, schema, table)}
    attributes = [
        dict(row)
        for row in connection.execute(
            sa.text(
                "SELECT a.attname,format_type(a.atttypid,a.atttypmod) AS type,a.attidentity, "
                "a.attgenerated,n.nspname AS collation_schema,c.collname AS collation "
                "FROM pg_attribute a LEFT JOIN pg_collation c ON c.oid=a.attcollation "
                "LEFT JOIN pg_namespace n ON n.oid=c.collnamespace "
                "WHERE a.attrelid=to_regclass(:table) AND a.attnum>0 AND NOT a.attisdropped "
                "ORDER BY a.attname"
            ),
            parameters,
        ).mappings()
    ]
    constraints = []
    for row in connection.execute(
        sa.text(
            "SELECT conname,contype,convalidated,connoinherit,condeferrable,condeferred, "
            "conislocal,coninhcount,pg_get_constraintdef(oid) AS definition "
            "FROM pg_constraint WHERE conrelid=to_regclass(:table)"
        ),
        parameters,
    ).mappings():
        value = dict(row)
        value["definition"] = (
            "audit-type-policy"
            if table == _AUDIT_TABLE and row["conname"] == _AUDIT_CHECK
            else _sql(row["definition"], schema)
        )
        constraints.append(value)
    indexes = []
    for row in connection.execute(
        sa.text(
            "SELECT c.relname,i.indisunique,i.indisprimary,i.indisvalid,i.indisready,i.indislive, "
            "i.indnullsnotdistinct,c.reloptions,pg_get_indexdef(c.oid) AS definition, "
            "c.relowner=t.relowner AS owner_matches_table, "
            "(SELECT json_agg(json_build_array(n.nspname,o.opcname) ORDER BY v.ordinality) "
            "FROM unnest(i.indclass::oid[]) WITH ORDINALITY v(oid,ordinality) "
            "JOIN pg_opclass o ON o.oid=v.oid "
            "JOIN pg_namespace n ON n.oid=o.opcnamespace) AS opclasses, "
            "(SELECT json_agg(json_build_array(n.nspname,o.collname) ORDER BY v.ordinality) "
            "FROM unnest(i.indcollation::oid[]) WITH ORDINALITY v(oid,ordinality) "
            "LEFT JOIN pg_collation o ON o.oid=v.oid "
            "LEFT JOIN pg_namespace n ON n.oid=o.collnamespace) AS collations "
            "FROM pg_index i JOIN pg_class c ON c.oid=i.indexrelid "
            "JOIN pg_class t ON t.oid=i.indrelid WHERE i.indrelid=to_regclass(:table)"
        ),
        parameters,
    ).mappings():
        value = dict(row)
        value["definition"] = _sql(row["definition"], schema)
        value["reloptions"] = sorted(value["reloptions"] or [])
        indexes.append(value)
    triggers = []
    for row in connection.execute(
        sa.text(
            "SELECT t.tgisinternal,t.tgtype,t.tgenabled,c.conname,p.proname,n.nspname, "
            "t.tgargs,CASE WHEN t.tgisinternal THEN NULL "
            "ELSE pg_get_triggerdef(t.oid) END AS definition "
            "FROM pg_trigger t LEFT JOIN pg_constraint c ON c.oid=t.tgconstraint "
            "JOIN pg_proc p ON p.oid=t.tgfoid JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE t.tgrelid=to_regclass(:table)"
        ),
        parameters,
    ).mappings():
        value = dict(row)
        value["tgargs"] = bytes(value["tgargs"]).hex()
        value["definition"] = _sql(row["definition"], schema) if row["definition"] else None
        triggers.append(value)
    options = dict(
        connection.execute(
            sa.text(
                "SELECT relkind,relpersistence,relispartition,relrowsecurity,"
                "relforcerowsecurity,reloptions "
                "FROM pg_class WHERE oid=to_regclass(:table)"
            ),
            parameters,
        )
        .mappings()
        .one()
    )
    options["reloptions"] = sorted(options["reloptions"] or [])
    policies = [
        dict(row)
        for row in connection.execute(
            sa.text(
                "SELECT polname,polcmd,polpermissive,pg_get_expr(polqual,polrelid) AS predicate, "
                "pg_get_expr(polwithcheck,polrelid) AS check_expression FROM pg_policy "
                "WHERE polrelid=to_regclass(:table)"
            ),
            parameters,
        ).mappings()
    ]
    return {
        "attributes": attributes,
        "constraints": _ordered(constraints),
        "indexes": _ordered(indexes),
        "triggers": _ordered(triggers),
        "options": options,
        "policies": _ordered(policies),
    }


def _sqlite_table(
    connection: Connection, table: str, audit_expression: str | None
) -> dict[str, Any]:
    definition = connection.scalar(
        sa.text("SELECT sql FROM sqlite_schema WHERE type='table' AND name=:table"),
        {"table": table},
    )
    tokens = _sql(str(definition), "main")
    start = tokens.index("(")
    parts: list[list[str]] = [[]]
    depth = 0
    end = start
    for end in range(start + 1, len(tokens)):
        token = tokens[end]
        if token == ")" and depth == 0:
            break
        if token == "," and depth == 0:
            parts.append([])
            continue
        parts[-1].append(token)
        depth += int(token == "(") - int(token == ")")
    if audit_expression is not None:
        pattern = _sql(audit_expression, "main")
        matches = 0
        for part in parts:
            for index in range(len(part) - len(pattern) + 1):
                if part[index : index + len(pattern)] == pattern:
                    part[index : index + len(pattern)] = ["audit-type-policy"]
                    matches += 1
                    break
        if matches != 1:
            raise RuntimeError("migration 0019 cannot identify the historical audit CHECK")
    indexes = []
    for name, sql in connection.execute(
        sa.text(
            "SELECT name,sql FROM sqlite_schema WHERE type='index' "
            "AND tbl_name=:table AND sql IS NOT NULL"
        ),
        {"table": table},
    ):
        entries = [
            [
                row["seqno"],
                "rowid" if row["cid"] == -1 else "expression" if row["cid"] == -2 else "column",
                row["name"],
                row["desc"],
                row["coll"],
                row["key"],
            ]
            for row in connection.execute(
                sa.text("SELECT * FROM pragma_index_xinfo(:name)"), {"name": name}
            ).mappings()
        ]
        indexes.append({"name": name, "definition": _sql(sql, "main"), "entries": entries})
    triggers = [
        [name, _sql(sql, "main")]
        for name, sql in connection.execute(
            sa.text("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name=:table"),
            {"table": table},
        )
    ]
    columns = [
        dict(row)
        for row in connection.execute(
            sa.text(
                'SELECT name,type,"notnull",dflt_value,pk,hidden FROM pragma_table_xinfo(:table)'
            ),
            {"table": table},
        ).mappings()
    ]
    return {
        "definition_parts": _ordered(parts),
        "options": tokens[end + 1 :],
        "columns": sorted(columns, key=lambda row: row["name"]),
        "indexes": _ordered(indexes),
        "triggers": _ordered(triggers),
    }


def schema_catalog(connection: Connection) -> dict[str, Any]:
    """Read structural identities and reject unsafe sequence high-water marks; never write."""
    schema = _namespace(connection)
    inspector = sa.inspect(connection)
    result = {}
    for table in inspector.get_table_names(schema=schema):
        checks = inspector.get_check_constraints(table, schema=schema)
        audit = next(
            (
                item["sqltext"]
                for item in checks
                if table == _AUDIT_TABLE and item["name"] == _AUDIT_CHECK
            ),
            None,
        )
        columns = []
        for column in inspector.get_columns(table, schema=schema):
            value = {
                "name": column["name"],
                "type": _sql(str(column["type"].compile(dialect=connection.dialect)), schema),
                "nullable": column["nullable"],
                "default": _default(connection, column.get("default"), table, schema),
                "identity": _json_value(column.get("identity"), schema),
                "computed": _json_value(column.get("computed"), schema),
            }
            if connection.dialect.name == "postgresql":
                owned = connection.scalar(
                    sa.text("SELECT pg_get_serial_sequence(:table,:column)"),
                    {"table": _qualified(connection, schema, table), "column": column["name"]},
                )
                value["owned_sequence"] = (
                    _sequence(connection, owned, table, schema) if owned else None
                )
                if owned:
                    sequence = value["owned_sequence"]
                    if sequence["schema"] is not None:
                        raise RuntimeError("migration 0019 refuses a foreign prerequisite sequence")
                    logical_table = sa.table(table, sa.column(column["name"]), schema=schema)
                    maximum = connection.scalar(
                        sa.select(sa.func.max(logical_table.c[column["name"]]))
                    )
                    logical_sequence = sa.table(
                        sequence["name"],
                        sa.column("last_value"),
                        sa.column("is_called"),
                        schema=sequence["schema"] or schema,
                    )
                    last, called = connection.execute(
                        sa.select(logical_sequence.c.last_value, logical_sequence.c.is_called)
                    ).one()
                    next_value = last + sequence["parameters"][2] if called else last
                    if maximum is not None and next_value <= maximum:
                        raise RuntimeError("migration 0019 refuses a lagging prerequisite sequence")
            columns.append(value)
        foreign_keys = inspector.get_foreign_keys(
            table,
            schema=schema,
            **(
                {"postgresql_ignore_search_path": True}
                if connection.dialect.name == "postgresql"
                else {}
            ),
        )
        for key in foreign_keys:
            if key.get("referred_schema") in {None, schema}:
                key["referred_schema"] = None
        value = {
            "columns": sorted(columns, key=lambda item: item["name"]),
            "pk": inspector.get_pk_constraint(table, schema=schema),
            "unique": _ordered(inspector.get_unique_constraints(table, schema=schema)),
            "foreign_keys": _ordered(foreign_keys),
            "indexes": _ordered(_json_value(inspector.get_indexes(table, schema=schema), schema)),
            "checks": _ordered(
                [
                    dict(
                        item,
                        sqltext=(
                            "audit-type-policy"
                            if table == _AUDIT_TABLE and item["name"] == _AUDIT_CHECK
                            else _sql(item["sqltext"], schema)
                        ),
                    )
                    for item in checks
                ]
            ),
        }
        if connection.dialect.name == "postgresql":
            value["native"] = _postgresql_table(connection, table, schema)
        else:
            value["native"] = _sqlite_table(connection, table, audit)
            if any("autoincrement" in part for part in value["native"]["definition_parts"]):
                primary = value["pk"]["constrained_columns"]
                if len(primary) != 1:
                    raise RuntimeError("migration 0019 refuses an unknown AUTOINCREMENT identity")
                logical_table = sa.table(table, sa.column(primary[0]))
                maximum = connection.scalar(sa.select(sa.func.max(logical_table.c[primary[0]])))
                high_water = connection.scalar(
                    sa.text("SELECT seq FROM sqlite_sequence WHERE name=:table"), {"table": table}
                )
                if maximum is not None and (high_water is None or high_water < maximum):
                    raise RuntimeError("migration 0019 refuses a lagging prerequisite sequence")
        result[table] = value
    return result


def catalog_hash(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


# Generated from the unchanged parent DDL, with only the shared audit policy represented by
# a marker. Its allowed expressions/types are independently checked by revision 0019.
EXPECTED_TABLE_HASHES: dict[str, dict[str, str]] = {
    "sqlite": {
        "alembic_version": ("0de124f24a22391d57f0944920707901ba96cb7c9f77317f151c8c499ee8b31b"),
        "patient_portal_accounts": (
            "80c8d836d09f56ac0e40e3cf8cdb6b226bac8e9f81c3f97e8bfaf33b4f1e4c23"
        ),
        "patient_portal_audit_events": (
            "821bc06eec3408e0cf6320f24efacabaf1eb917e221051f333247fd5d4370055"
        ),
        "patient_portal_booking_choices": (
            "af295ac99770a1a2241dce21ed790ba955e086b08dcfc92fbbfb392d44cd7608"
        ),
        "patient_portal_booking_offered_slots": (
            "9d444e09e788014f2c8ed0de762481be68bbf7e086dfcee559f0ccf7f65cd8e0"
        ),
        "patient_portal_booking_prompts": (
            "ee1c6877d0e6ca6548054032ea59d83f3b58b926c2f993debbed08d86ede0adb"
        ),
        "patient_portal_clinic_keys": (
            "f54e99aa59de52187f52be4c617271b7251ae231fe7a79c3fb70d1e71d07e1ac"
        ),
        "patient_portal_contact_review_requests": (
            "787363b3df6e51c237b92f6c070c4ced96e007216044be3a5f5c198cfda98164"
        ),
        "patient_portal_email_change_requests": (
            "2e635c51bf4b9954a4b386a99d3617cb01312d1e99542f8b08787f454b16e14e"
        ),
        "patient_portal_invites": (
            "1386897ba14ba12745e0ef4b291f3460d189b519f81f8bb9514784364b928f79"
        ),
        "patient_portal_mfa_challenges": (
            "0e0a91997f8a9ef419d8bdc3ade742e682875e6d7abf13029acc4a995fd662d4"
        ),
        "patient_portal_mycarlos_approval_clinics": (
            "89134f0d718a879c8e60dc61a8ed57e941fb4f30b0a993948e1ff93c51058112"
        ),
        "patient_portal_mycarlos_approval_requests": (
            "a076581074eddf3d5536ac784064bee1a70dbc4b4aada0f4705bcb0299e26a29"
        ),
        "patient_portal_mycarlos_devices": (
            "f20306e80f83104ff755f1953c2b75cfbcf198ca9ffa117697b74aeb2662023d"
        ),
        "patient_portal_mycarlos_link_codes": (
            "6368bc30bb063a40cb5f717bfb5b29e36852d4cadb4059fc6a6e6e06a0458031"
        ),
        "patient_portal_mycarlos_link_failures": (
            "f3168d5b77420cb690d81539aa37790cbbc01742aa7ece9a8cb8a6172f33c0b0"
        ),
        "patient_portal_mycarlos_mailbox_accounts": (
            "8c9f722b133b700963d35b5230dc975118219c366a6d40927ec2c1b6885a20fb"
        ),
        "patient_portal_mycarlos_mailbox_anchors": (
            "fc0e78d1022ef3edb1579bf8d3a768b087ee46532d9478c9ae4e81b0560c13e0"
        ),
        "patient_portal_mycarlos_mailbox_blobs": (
            "38f16eff8d024af2f7233934eed11c83624c4f8c43920260b4e38e04e8277803"
        ),
        "patient_portal_mycarlos_mailbox_clinics": (
            "dc836ad2f8f79b8661fbbe72c0b7ca3791246f8a962174ca7b6a0bd8afb8fdfb"
        ),
        "patient_portal_mycarlos_mailbox_copies": (
            "080e4f3af53a1d2a7430b74aec15cbc4d21a40813ae83e6588fc189b4bc20fef"
        ),
        "patient_portal_mycarlos_mailbox_devices": (
            "e31c5e31c5e37354414910de21255ce1bd8f26e9cb6703233394eddcffff7e70"
        ),
        "patient_portal_mycarlos_mailbox_events": (
            "9fd0d1d42de11c0f5a4999b34428dfd407c6e9544d9515f22d9f689790b3ee6c"
        ),
        "patient_portal_mycarlos_mailbox_proofs": (
            "5948aa179df61e126ed8defb02b516e505a060af2c878feb747c3c116e5a82d6"
        ),
        "patient_portal_mycarlos_mailbox_rates": (
            "57fd356e71d865a6f44748e713318088d2645ee4e51deddddccbd5961486e518"
        ),
        "patient_portal_mycarlos_recipients": (
            "02ec270c7b21a078a8703be6e4c281d6870f74dbbf431639ecc67a929ae7c1c7"
        ),
        "patient_portal_outbound_deliveries": (
            "c0888c6f9bba70a4d4e0299b057a866d91fd67452f69630db71c8d3dab57b2a0"
        ),
        "patient_portal_password_reset_tokens": (
            "9a125769ee1413fe12c8bdff09adfaf5885012c2e01341d485327eb8fba273e1"
        ),
        "patient_portal_sessions": (
            "1f99d71153f8a0ab8152fc7d623729a4dcaae411728e0949f13bfc8d624fd180"
        ),
        "patient_portal_signup_requests": (
            "383cde772d83f210ed56bccbca7e7fd964d31a5d8c1bec9e40b17720ae92897e"
        ),
        "patient_portal_staff_assertion_uses": (
            "884aa545bf6107fc1ab38a01f376889748288a4c55ff7b6b25f2ef816fb4991b"
        ),
        "patient_portal_unlock_secrets": (
            "9ea01d7eb85a50565ce7e545b7911b8c3d584a57cb20ba0a981c0c7ae9e5e3a6"
        ),
    },
    "postgresql": {
        "alembic_version": ("8c3471c514727d99092d98c622409921a7df4b9c4edc1b7a8a93dac8472a54fa"),
        "patient_portal_accounts": (
            "8240dd18e5e777f3ab6c3c7e200e88d16bcb1793f088cb90d5beaeb33797ddd7"
        ),
        "patient_portal_audit_events": (
            "292a850831fccafbf764f952a2fca9c33cf9c0d744c2fd4edca74b83f59921b7"
        ),
        "patient_portal_booking_choices": (
            "94eb111295d926d72fe86974b29506ad8b63a0ebc79031aa0a6d81230966758e"
        ),
        "patient_portal_booking_offered_slots": (
            "72d73c6c0d16a8cbce8bf6a97311f64080e1a259bb135d305a41c403929715a5"
        ),
        "patient_portal_booking_prompts": (
            "0b59ecba7bf0af7aaf885e5d64d220829c5ba26510e40debbdb410e9cde3c1b3"
        ),
        "patient_portal_clinic_keys": (
            "ccda86c0b43ff38e220c92565cd2b511f42278067408cceb8baaf8800f455bea"
        ),
        "patient_portal_contact_review_requests": (
            "346fcffaf3780ede8647a25c3dc18c9638b2fc70aa9672e1542fc2fd75e7ddd4"
        ),
        "patient_portal_email_change_requests": (
            "76a8dc45f2c6b02d329d4743433568ddd37d33a3bf8088cc33d18f2f332661be"
        ),
        "patient_portal_invites": (
            "d4ebcaf34c583cb97b0747479021496b56eced8d8503b42d16f76f20f12107bb"
        ),
        "patient_portal_mfa_challenges": (
            "9d7f032414d47fb75babecf23a11e243be8425df2c5d97d4b77c9863bb19e264"
        ),
        "patient_portal_mycarlos_approval_clinics": (
            "03c6bc63dfd7274b35a3942892b683805aa7b591249cd8d18a09c0bae67f737b"
        ),
        "patient_portal_mycarlos_approval_requests": (
            "cdcffcbb8253571c99c525c4109cc5a6de10ff6c149549737c33d23446b1fbd4"
        ),
        "patient_portal_mycarlos_devices": (
            "b2e4e809830f825be544f022c5bd3d9e6f7426fb6674c5890aa2f7a53e7c7096"
        ),
        "patient_portal_mycarlos_link_codes": (
            "5fcbfcda9c232095d6defa60efc998b628d8e67943dfd7bc62ce582fcb51bded"
        ),
        "patient_portal_mycarlos_link_failures": (
            "59ffadb92a514dd2b33b657df15d0caca25fb940c6a26506a76b6b7ed8d7a2ff"
        ),
        "patient_portal_mycarlos_mailbox_accounts": (
            "d6532cb171aa50660b6c8beba3f18635d4b6a13b937f03746a14baedc067b245"
        ),
        "patient_portal_mycarlos_mailbox_anchors": (
            "434b45a73c6304e5b82ace73859eeae54ac018fd3e2562b175e9879803d0118c"
        ),
        "patient_portal_mycarlos_mailbox_blobs": (
            "b7572c8c69de69cb828e7c4dd7d91ded18b8d0c165bbc67fe475195cdf50f785"
        ),
        "patient_portal_mycarlos_mailbox_clinics": (
            "7c6acb7516214292203618c0d662ca267a203df1180ed4cda3b1e20665a18fba"
        ),
        "patient_portal_mycarlos_mailbox_copies": (
            "baadfa36ed3713c500917f782ab74019480af966161c768cd584e8ccd0704776"
        ),
        "patient_portal_mycarlos_mailbox_devices": (
            "b7406cbd467465f7355fad2436489e05d949daeada9ee378f9b0a6a9e04b9b0a"
        ),
        "patient_portal_mycarlos_mailbox_events": (
            "23d8b8f211342904f202fedf0880cdf4b152e28c78ae4765801d9359b5e608fb"
        ),
        "patient_portal_mycarlos_mailbox_proofs": (
            "e0a20bee8664f899ce4aafb155edfa96dcc2a03fd7e1cb3ff356390924afe683"
        ),
        "patient_portal_mycarlos_mailbox_rates": (
            "8ff135ce90999f48d885469b4d4e9b26d296ed60505b009fc56f7975001645cd"
        ),
        "patient_portal_mycarlos_recipients": (
            "f2eb4ba2238b8a54b256eba4d1c132307961a9d5558a799cff43ea9e29d0cd25"
        ),
        "patient_portal_outbound_deliveries": (
            "2d93eda45ec409943003f5245f8810a37b2ecc25624de92ad3d717e37e97cb7b"
        ),
        "patient_portal_password_reset_tokens": (
            "c0be1210a978a9a11a69c454e52b7b4513c6fd5ff1f38ba3af6c3203fa86b823"
        ),
        "patient_portal_sessions": (
            "0ec949884df62a235e9b151477c8c23029a1e492170ff86d1c63b69307b3ad21"
        ),
        "patient_portal_signup_requests": (
            "d573fa7c066001ebaeea74837f681a3b2ff3f9a4f222a7c3072fcec9d6f47062"
        ),
        "patient_portal_staff_assertion_uses": (
            "88906f8f07a17e902d8b71691ba0bf6ac41de29ee10501617ec32b8c37473984"
        ),
        "patient_portal_unlock_secrets": (
            "65cf564044f027aa91f8c87f43e97503cbd2e5b09d1336b6e25722a9b5729d78"
        ),
    },
}


def verify_schema(connection: Connection) -> None:
    """Refuse any unrecognized prerequisite identity before the merge can write."""
    expected = EXPECTED_TABLE_HASHES[connection.dialect.name]
    schema = _namespace(connection)
    if set(sa.inspect(connection).get_table_names(schema=schema)) != set(expected):
        raise RuntimeError("migration 0019 refuses missing or unexpected prerequisite tables")
    actual = schema_catalog(connection)
    for table, digest in expected.items():
        if catalog_hash(actual[table]) != digest:
            raise RuntimeError("migration 0019 refuses physical schema drift in " + table)
