from contextlib import asynccontextmanager

from fastapi import FastAPI

from learn_auth.app.api.v1.routers import router
from learn_auth.app.core.config import settings
from learn_auth.app.core.database import init_db, seed_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup code here
    print("Starting up the application...")
    # init database (create tables)
    if not settings.SKIP_DB_INIT:  # add a setting to skip db init if needed
        init_db()

    # seed database with initial data (development/learning only)
    # Set SEED_DB=true in .env or os.environ to enable seeding
    if settings.DEBUG:  # or add a SEED_DB setting
        seed_db()

    yield
    # Shutdown code here
    print("Shutting down the application...")


app = FastAPI(app_name=settings.APP_NAME, debug=settings.DEBUG, lifespan=lifespan)


@app.get("/")
def health_check():
    return {"status": "ok"}


app.include_router(router=router, prefix="/api/v1")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
