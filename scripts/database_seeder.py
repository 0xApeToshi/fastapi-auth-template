"""
Main database seeder utility to populate the database with initial data.

This script runs all seeding operations in sequence.

Usage:
    python -m scripts.database_seeder [--admin] [--test-users COUNT] [--reset]

Options:
    --admin           Create an admin user (admin@example.com / admin123)
    --test-users      Create test users
    COUNT             Number of test users to create (default: 10)
    --reset           Reset the database before seeding (WARNING: This deletes all data!)
"""
import asyncio
import argparse
import os
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import delete, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import Base
from app.db.session import AsyncSessionLocal, engine
from app.models.user import User, BlacklistedToken

# Import seed functions
from scripts.seed_admin import create_admin
from scripts.seed_test_users import create_test_users, list_users


async def reset_database():
    """
    Reset the database by dropping all tables and recreating them.
    WARNING: This deletes all data!
    """
    print("WARNING: You are about to reset the database and lose all data!")
    confirmation = input("Are you sure you want to continue? (y/N): ")
    
    if confirmation.lower() != 'y':
        print("Database reset cancelled.")
        return False
    
    print("Resetting database...")
    
    # Drop all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    
    # Recreate all tables
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    print("Database has been reset successfully.")
    return True


async def truncate_tables():
    """
    Truncate all tables without dropping them.
    This is faster than dropping and recreating tables.
    """
    print("Truncating tables...")
    
    async with AsyncSessionLocal() as session:
        # Truncate users table
        await session.execute(delete(User))
        
        # Truncate blacklisted_tokens table
        await session.execute(delete(BlacklistedToken))
        
        await session.commit()
    
    print("Tables truncated successfully.")


async def seed_database(args):
    """
    Seed the database with initial data.
    
    Args:
        args: Command line arguments
    """
    if args.reset:
        reset_success = await reset_database()
        if not reset_success:
            return
    
    # Create admin user if requested
    if args.admin:
        await create_admin("admin@example.com", "admin123")
    
    # Create test users if requested
    if args.test_users > 0:
        await create_test_users(args.test_users)
    
    # Always list users at the end
    await list_users()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the database with initial data.")
    parser.add_argument("--admin", action="store_true", help="Create an admin user")
    parser.add_argument("--test-users", type=int, default=0, help="Number of test users to create")
    parser.add_argument("--reset", action="store_true", help="Reset the database before seeding")
    
    args = parser.parse_args()
    
    # Run at least one operation
    if not (args.admin or args.test_users > 0):
        parser.print_help()
        print("\nError: No seeding operations specified.")
        print("Please use at least one of: --admin, --test-users")
        sys.exit(1)
    
    asyncio.run(seed_database(args))