import importlib
import os
import pkgutil
import re
from datetime import datetime
from logging.config import fileConfig

from sqlalchemy import text

import learn_auth.app.models as models_pkg
from alembic import context
from learn_auth.app.core.config import settings
from learn_auth.app.core.database import Base, engine

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = Base.metadata

# Automatically import all modules in the models package so that
# SQLAlchemy registers every model before running migrations.
for module_info in pkgutil.iter_modules(models_pkg.__path__):
    importlib.import_module(f"learn_auth.app.models.{module_info.name}")


# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.
def generate_date_serial_rev_id() -> str:
    """Generate a revision ID in YYYY_MM_DD_NNN format."""
    date_str = datetime.now().strftime("%Y_%m_%d")
    versions_dir = os.path.join(os.path.dirname(__file__), "versions")

    pattern = re.compile(rf"^{date_str}_(\d{{3}})_")
    max_serial = 0

    if os.path.exists(versions_dir):
        for fname in os.listdir(versions_dir):
            m = pattern.match(fname)
            if m:
                max_serial = max(max_serial, int(m.group(1)))

    return f"{date_str}_{max_serial + 1:03d}"


def include_object(object, name, type_, reflected, compare_to):
    """Restrict autogenerate to only the target schema.

    Without this filter, include_schemas=True causes Alembic to scan ALL
    schemas (including 'public') and generate spurious DROP statements for
    any tables found there that are not part of the models.
    """
    if type_ == "table":
        return object.schema == settings.SCHEMA
    return True


def process_revision_directives(context, revision, directives):
    """Hook called during `alembic revision` to override the rev ID."""
    if directives:
        directives[0].rev_id = generate_date_serial_rev_id()


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = engine.url
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        ## These two args required for Alembic to generate correct CREATE TABLE statements with schema
        include_schemas=True,
        version_table_schema=settings.SCHEMA,
        include_object=include_object,
        process_revision_directives=process_revision_directives,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    connectable = engine

    with connectable.connect() as connection:
        # Ensure schema exists before migrations run
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{settings.SCHEMA}"'))
        connection.execute(text(f'SET search_path TO "{settings.SCHEMA}", public'))
        connection.commit()

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            ## These two args required for Alembic to generate correct CREATE TABLE statements with schema
            include_schemas=True,
            version_table_schema=settings.SCHEMA,
            # render_as_batch=True, ## Only needed for SQLite, not needed for Postgres
            include_object=include_object,
            process_revision_directives=process_revision_directives,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
