# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from carlos_patient_portal import models
from carlos_patient_portal.config import get_migration_database_url

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = models.Base.metadata


def get_url() -> str:
    configured_url = config.get_main_option("sqlalchemy.url")
    if configured_url:
        return configured_url
    return get_migration_database_url()


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    # An embedding caller (the test harness, or anything migrating a database it already holds open)
    # can hand us a live connection. Honouring it matters for in-memory SQLite, where building a
    # second engine would silently migrate a different, throwaway database. The connection is not
    # closed here because it belongs to the caller.
    existing_connection = config.attributes.get("connection")
    if existing_connection is not None:
        context.configure(connection=existing_connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        return

    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
