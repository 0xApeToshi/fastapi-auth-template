"""
Seed script to create an admin user in the database.

Usage:
    python -m scripts.seed_admin [email] [password]

If email and password are not provided, they will be prompted for.
"""
import asyncio
import os
import sys
from getpass import getpass

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import select

from app.core.security import get_password_hash
from app.db.session import AsyncSessionLocal
from app.models.user import User, UserRole


async def create_admin(email: str = None, password: str = None):
    """Create an admin user in the database."""
    print("Creating admin user...")
    
    # Get admin details if not provided
    if not email:
        email = input("Enter admin email: ")
    
    if not password:
        password = getpass("Enter admin password: ")
        confirm_password = getpass("Confirm admin password: ")
        
        if password != confirm_password:
            print("Passwords do not match!")
            return
    
    if len(password) < 8:
        print("Password must be at least 8 characters long!")
        return
    
    # Hash the password
    hashed_password = get_password_hash(password)
    
    # Create the admin user
    async with AsyncSessionLocal() as session:
        try:
            # Check if user already exists
            result = await session.execute(select(User).where(User.email == email))
            existing_user = result.scalars().first()
            
            if existing_user:
                print(f"User with email {email} already exists!")
                if existing_user.role != UserRole.ADMIN:
                    print(f"Updating role to ADMIN for user {email}")
                    existing_user.role = UserRole.ADMIN
                    await session.commit()
                    print(f"User {email} is now an admin!")
                return
            
            # Create new admin user
            admin_user = User(
                email=email,
                hashed_password=hashed_password,
                role=UserRole.ADMIN,
                is_active=True,
            )
            
            session.add(admin_user)
            await session.commit()
            
            print(f"Admin user {email} created successfully!")
            
        except Exception as e:
            await session.rollback()
            print(f"Error creating admin user: {e}")


if __name__ == "__main__":
    # Get command line arguments if provided
    email = sys.argv[1] if len(sys.argv) > 1 else None
    password = sys.argv[2] if len(sys.argv) > 2 else None
    
    asyncio.run(create_admin(email, password))