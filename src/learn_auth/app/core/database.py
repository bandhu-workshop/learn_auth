from sqlalchemy import create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from learn_auth.app.core.config import settings

# Create the SQLAlchemy engine
engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
)

# Create sessionmaker factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Create a base class for our models
Base = declarative_base()


# init db
def init_db():
    # Automatically import all modules in the models package so that
    # SQLAlchemy registers every model before creating tables.
    import importlib
    import pkgutil

    import learn_auth.app.models as models_pkg

    for module_info in pkgutil.iter_modules(models_pkg.__path__):
        importlib.import_module(f"learn_auth.app.models.{module_info.name}")

    with engine.connect() as conn:
        conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{settings.SCHEMA}"'))
        conn.commit()

    Base.metadata.create_all(bind=engine)
    print("✅ Database tables initialized")
