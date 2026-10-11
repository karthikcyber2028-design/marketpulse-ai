"""IoT Vulnerability Tracker - Startup Script"""
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "backend"))


async def main():
    if len(sys.argv) > 1 and sys.argv[1] == "seed":
        print("Seeding database...")
        from app.seed import seed
        await seed()
        print("Done!")
    elif len(sys.argv) > 1 and sys.argv[1] == "test":
        print("Running tests...")
        os.system("cd backend && python -m pytest tests/ -v")
    else:
        import uvicorn
        from app.config import settings
        print(f"Starting {settings.app_name} v{settings.app_version}")
        print(f"API docs: http://{settings.api_host}:{settings.api_port}/docs")
        print(f"Dashboard: http://{settings.api_host}:{settings.api_port}/")
        uvicorn.run(
            "app.main:app",
            host=settings.api_host,
            port=settings.api_port,
            reload=settings.debug,
            app_dir="backend",
        )


if __name__ == "__main__":
    asyncio.run(main())
