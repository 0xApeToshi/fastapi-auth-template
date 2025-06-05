# fastapi-auth-template

A robust FastAPI application implementing user management with authentication using JWT tokens and Argon2 password hashing.

## Features

- User registration and management (CRUD operations)
- Authentication with JWT tokens (access and refresh tokens)
- Role-based authorization (admin and regular users)
- Password hashing with Argon2 (state-of-the-art algorithm)
- Async database operations with SQLAlchemy 1.4+
- Clean architecture with dependency injection
- Database migrations with Alembic
- Containerized with Docker

## Project Structure

The project follows a clean architecture approach with clear separation of concerns:

- **API**: Handles HTTP requests/responses
- **Services**: Contains business logic
- **Repositories**: Handles data access
- **Models**: SQLAlchemy database models
- **Schemas**: Pydantic validation schemas
- **Core**: Configuration and utilities

## Requirements

- Python 3.8+
- PostgreSQL 12+
- Docker and Docker Compose (optional)

## Getting Started

### Setup with Docker

1. Clone the repository
2. Copy `.env.example` to `.env` and adjust the values
3. Run the application with Docker Compose:

```bash
docker-compose up -d
```

4. Apply migrations:

```bash
docker-compose exec web alembic upgrade head
```

### Manual Setup

1. Clone the repository
2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Copy `.env.example` to `.env` and adjust the values
4. Start PostgreSQL server and create database
5. Apply migrations:

```bash
alembic upgrade head
```

6. Run the application:

```bash
uvicorn app.main:app --reload
```

## API Endpoints

### Authentication

- `POST /api/v1/auth/login` - Authenticate user and get tokens
- `POST /api/v1/auth/refresh` - Refresh access token
- `POST /api/v1/auth/logout` - Logout user (invalidate tokens)

### Users

- `POST /api/v1/users` - Create new user
- `GET /api/v1/users/me` - Get current user profile
- `PUT /api/v1/users/me` - Update current user profile
- `GET /api/v1/users` - List all users (admin only)
- `GET /api/v1/users/{user_id}` - Get user by ID (admin only)
- `PUT /api/v1/users/{user_id}` - Update user (admin only)
- `DELETE /api/v1/users/{user_id}` - Delete user (admin only)

## Authentication Flow

1. **Registration**: User registers with email and password
2. **Login**: User authenticates and receives access and refresh tokens
3. **API Access**: User includes access token in Authorization header
4. **Token Refresh**: When access token expires, use refresh token to get new tokens
5. **Logout**: Invalidate tokens by adding them to blacklist

## Development

### Running Tests

```bash
pytest
```

### Database Migrations

Create a new migration:

```bash
alembic revision --autogenerate -m "Description"
```

Apply migrations:

```bash
alembic upgrade head
```

## Security Features

- Argon2 password hashing (winner of the Password Hashing Competition)
- JWT tokens with proper expiration
- Token blacklisting for logout
- Role-based access control
- Input validation with Pydantic

## License

This project is licensed under the MIT License - see the LICENSE file for details.