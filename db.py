from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from config import settings
from schemas import Base

engine = create_async_engine(url=settings.DATABASE_URL, echo=True)


async def get_session():
    SessionLocal = sessionmaker(bind=engine, class_=AsyncSession)
    async_session = SessionLocal()
    yield async_session


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    # This function is called during the application shutdown
    try:
        # Close the database session or connection
        async with AsyncSession(engine) as session:
            # Perform any additional cleanup or finalization
            # For example, commit any pending changes before closing
            await session.commit()
    except Exception as e:
        # Handle exceptions if any error occurs during cleanup
        print(f"Error during database cleanup: {e}")
    finally:
        # Close the database engine to release resources
        engine.dispose()