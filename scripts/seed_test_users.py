"""
Seed script to create test users in the database.

Usage:
    python -m scripts.seed_test_users [count]

If count is not provided, 10 test users will be created.
"""
import asyncio
import os
import sys
import random
from typing import List

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import get_password_hash
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole


# Test email domains for variety
EMAIL_DOMAINS = ["example.com", "test.com", "mail.org", "testuser.net", "demo.io"]


async def create_test_users(count: int = 10):
    """
    Create test users in the database.
    
    Args:
        count: Number of test users to create
    """
    print(f"Creating {count} test users...")
    
    # Standard password for all test users
    password = "password123"
    hashed_password = get_password_hash(password)
    
    async with AsyncSessionLocal() as session:
        try:
            # Create test users
            for i in range(1, count + 1):
                # Generate random domain for variety
                domain = random.choice(EMAIL_DOMAINS)
                email = f"user{i}@{domain}"
                
                # Check if user already exists
                result = await session.execute(select(User).where(User.email == email))
                existing_user = result.scalars().first()
                
                if existing_user:
                    print(f"User with email {email} already exists, skipping...")
                    continue
                
                # Create new user (1 in 5 users will be admin for testing)
                is_admin = (i % 5 == 0)
                role = UserRole.ADMIN if is_admin else UserRole.REGULAR
                
                user = User(
                    email=email,
                    hashed_password=hashed_password,
                    role=role,
                    is_active=True,
                )
                
                session.add(user)
                print(f"Created user: {email} (Role: {role.value})")
            
            await session.commit()
            print(f"Successfully created test users!")
            
        except Exception as e:
            await session.rollback()
            print(f"Error creating test users: {e}")


async def list_users():
    """List all users in the database."""
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).order_by(User.id))
        users = result.scalars().all()
        
        print("\nUsers in database:")
        print("-" * 50)
        print(f"{'ID':<5} {'Email':<30} {'Role':<10} {'Active':<10}")
        print("-" * 50)
        
        for user in users:
            print(f"{user.id:<5} {user.email:<30} {user.role.value:<10} {'Yes' if user.is_active else 'No':<10}")


if __name__ == "__main__":
    # Get command line arguments if provided
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    
    async def main():
        await create_test_users(count)
        await list_users()
    
    asyncio.run(main())