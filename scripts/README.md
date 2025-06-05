# Database Seeding Scripts

This directory contains scripts for seeding the database with initial data. These are useful for development, testing, and initializing new deployments.

## Available Scripts

### Main Seeder Utility

```bash
python -m scripts.database_seeder [--admin] [--test-users COUNT] [--reset]
```

**Options:**
- `--admin` - Create an admin user (admin@example.com / admin123)
- `--test-users COUNT` - Create COUNT test users (default: 10)
- `--reset` - Reset the database before seeding (WARNING: Deletes all data!)

**Examples:**
```bash
# Create admin user and 10 test users
python -m scripts.database_seeder --admin --test-users 10

# Reset database and create admin user
python -m scripts.database_seeder --reset --admin

# Create 5 test users
python -m scripts.database_seeder --test-users 5
```

### Individual Scripts

#### Create Admin User

```bash
python -m scripts.seed_admin [email] [password]
```

If email and password are not provided, you will be prompted to enter them.

**Example:**
```bash
# Create admin with specified credentials
python -m scripts.seed_admin admin@example.com mysecretpassword

# Create admin with prompted credentials
python -m scripts.seed_admin
```

#### Create Test Users

```bash
python -m scripts.seed_test_users [count]
```

Creates `count` test users with the password "password123". If count is not provided, 10 users will be created.

**Example:**
```bash
# Create 20 test users
python -m scripts.seed_test_users 20
```

## Usage Notes

1. All scripts automatically list users after execution to verify the changes.
2. These scripts should generally only be used in development and testing environments.
3. For production, use the admin script with a secure password to create the initial admin user.
4. When using the `--reset` option, be very careful as it deletes ALL data in the database.

## Test User Credentials

All test users created with `seed_test_users.py` have the following credentials:
- Password: `password123`
- Email format: `user{number}@{domain}` (e.g., user1@example.com)
- Every 5th user is an admin (user5, user10, etc.)