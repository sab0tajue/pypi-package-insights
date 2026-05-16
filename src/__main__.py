"""Entry point invoked by the Apify platform."""
import asyncio
from .main import main

if __name__ == "__main__":
    asyncio.run(main())
