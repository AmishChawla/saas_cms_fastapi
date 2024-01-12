from fastapi import FastAPI
from contextlib import asynccontextmanager
# from fastapi.middleware.lifespan import LifespanMiddleware
from config import settings
from db import init_db, close_db



# lifespan code
#
# @asynccontextmanager
# async def lifespan(app:FastAPI):
#     await init_db()
#
#     yield
from main import router


async def on_startup():
    await init_db()


async def on_shutdown():
    await close_db()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await on_startup()

    yield

    await on_shutdown()

def create_app():
    app = FastAPI(
        description="",
        title="ResumeParserAPI",
        version=settings.VERSION,
        lifespan=lifespan
    )
    app.include_router(router)
    app.add_event_handler("startup", on_startup)
    app.add_event_handler("shutdown", on_shutdown)
    # app.add_middleware(lifespan)
    # app.add_middleware(LifespanMiddleware)

    return app




app = create_app()
