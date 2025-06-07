from datetime import datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

from app.repositories.token import TokenCleanupScheduler, TokenRepository


@pytest.mark.asyncio
async def test_token_repository_blacklist(test_db):
    """Test TokenRepository blacklist method."""
    token_repository = TokenRepository(test_db)

    token = "test_token_123"
    expires_at = datetime.utcnow() + timedelta(hours=1)

    # Blacklist token
    blacklisted_token = await token_repository.blacklist(token, expires_at)

    assert blacklisted_token is not None
    assert blacklisted_token.token == token
    assert blacklisted_token.expires_at == expires_at
    assert blacklisted_token.blacklisted_at is not None
    assert blacklisted_token.id is not None


@pytest.mark.asyncio
async def test_token_repository_is_blacklisted_true(test_db):
    """Test TokenRepository is_blacklisted with blacklisted token."""
    token_repository = TokenRepository(test_db)

    token = "blacklisted_token_123"
    expires_at = datetime.utcnow() + timedelta(hours=1)

    # Blacklist token
    await token_repository.blacklist(token, expires_at)

    # Check if blacklisted
    is_blacklisted = await token_repository.is_blacklisted(token)

    assert is_blacklisted is True


@pytest.mark.asyncio
async def test_token_repository_is_blacklisted_false(test_db):
    """Test TokenRepository is_blacklisted with non-blacklisted token."""
    token_repository = TokenRepository(test_db)

    token = "not_blacklisted_token_123"

    # Check if blacklisted (without blacklisting it first)
    is_blacklisted = await token_repository.is_blacklisted(token)

    assert is_blacklisted is False


@pytest.mark.asyncio
async def test_token_repository_clean_expired_tokens(test_db):
    """Test TokenRepository clean_expired_tokens method."""
    token_repository = TokenRepository(test_db)

    current_time = datetime.utcnow()

    # Add expired tokens
    expired_token1 = "expired_token_1"
    expired_token2 = "expired_token_2"
    expired_time = current_time - timedelta(hours=1)  # 1 hour ago

    await token_repository.blacklist(expired_token1, expired_time)
    await token_repository.blacklist(expired_token2, expired_time)

    # Add non-expired token
    valid_token = "valid_token"
    future_time = current_time + timedelta(hours=1)  # 1 hour from now

    await token_repository.blacklist(valid_token, future_time)

    # Clean expired tokens - no parameter needed, uses current time internally
    cleaned_count = await token_repository.clean_expired_tokens()

    assert cleaned_count == 2  # Should clean 2 expired tokens

    # Verify expired tokens are gone
    assert await token_repository.is_blacklisted(expired_token1) is False
    assert await token_repository.is_blacklisted(expired_token2) is False

    # Verify valid token is still there
    assert await token_repository.is_blacklisted(valid_token) is True


@pytest.mark.asyncio
async def test_token_repository_clean_expired_tokens_none_expired(test_db):
    """Test TokenRepository clean_expired_tokens with no expired tokens."""
    token_repository = TokenRepository(test_db)

    current_time = datetime.utcnow()

    # Add only non-expired tokens
    valid_token1 = "valid_token_1"
    valid_token2 = "valid_token_2"
    future_time = current_time + timedelta(hours=1)

    await token_repository.blacklist(valid_token1, future_time)
    await token_repository.blacklist(valid_token2, future_time)

    # Clean expired tokens - no parameter needed
    cleaned_count = await token_repository.clean_expired_tokens()

    assert cleaned_count == 0  # Should clean 0 tokens

    # Verify tokens are still there
    assert await token_repository.is_blacklisted(valid_token1) is True
    assert await token_repository.is_blacklisted(valid_token2) is True


@pytest.mark.asyncio
async def test_token_repository_clean_expired_tokens_empty_table(test_db):
    """Test TokenRepository clean_expired_tokens with empty table."""
    token_repository = TokenRepository(test_db)

    # Clean expired tokens from empty table - no parameter needed
    cleaned_count = await token_repository.clean_expired_tokens()

    assert cleaned_count == 0


@pytest.mark.asyncio
async def test_token_repository_get_expired_token_count(test_db):
    """Test TokenRepository get_expired_token_count method."""
    token_repository = TokenRepository(test_db)

    current_time = datetime.utcnow()

    # Initially no expired tokens - no parameter needed
    count = await token_repository.get_expired_token_count()
    assert count == 0

    # Add expired tokens
    expired_time = current_time - timedelta(hours=1)
    await token_repository.blacklist("expired_1", expired_time)
    await token_repository.blacklist("expired_2", expired_time)

    # Add valid token
    future_time = current_time + timedelta(hours=1)
    await token_repository.blacklist("valid_1", future_time)

    # Check expired count - no parameter needed
    count = await token_repository.get_expired_token_count()
    assert count == 2


@pytest.mark.asyncio
async def test_token_repository_blacklist_multiple_tokens(test_db):
    """Test TokenRepository blacklist with multiple tokens."""
    token_repository = TokenRepository(test_db)

    tokens = ["token_1", "token_2", "token_3"]
    expires_at = datetime.utcnow() + timedelta(hours=1)

    # Blacklist multiple tokens
    for token in tokens:
        blacklisted_token = await token_repository.blacklist(token, expires_at)
        assert blacklisted_token.token == token

    # Verify all tokens are blacklisted
    for token in tokens:
        is_blacklisted = await token_repository.is_blacklisted(token)
        assert is_blacklisted is True


@pytest.mark.asyncio
async def test_token_repository_blacklist_duplicate_token(test_db):
    """Test TokenRepository blacklist with duplicate token (should raise error)."""
    token_repository = TokenRepository(test_db)

    token = "duplicate_token"
    expires_at = datetime.utcnow() + timedelta(hours=1)

    # Blacklist token first time
    await token_repository.blacklist(token, expires_at)

    # Try to blacklist same token again - should raise an integrity error
    with pytest.raises(Exception):  # Could be IntegrityError or similar
        await token_repository.blacklist(token, expires_at)


@pytest.mark.asyncio
async def test_token_repository_clean_expired_boundary_time(test_db):
    """Test TokenRepository clean_expired_tokens with boundary time conditions."""
    token_repository = TokenRepository(test_db)

    current_time = datetime.utcnow()

    # Add token that expires exactly now
    boundary_token = "boundary_token"
    exact_current_time = current_time

    await token_repository.blacklist(boundary_token, exact_current_time)

    # Add token that expires 1 second ago
    expired_token = "expired_token"
    one_second_ago = current_time - timedelta(seconds=1)

    await token_repository.blacklist(expired_token, one_second_ago)

    # Add token that expires 1 second from now
    future_token = "future_token"
    one_second_future = current_time + timedelta(seconds=1)

    await token_repository.blacklist(future_token, one_second_future)

    # Clean expired tokens - no parameter needed
    cleaned_count = await token_repository.clean_expired_tokens()

    # Should clean tokens that expire before current time
    # The boundary token (expires exactly now) might or might not be cleaned
    # depending on microsecond precision, but expired_token should definitely be cleaned
    assert cleaned_count >= 1

    # Future token should still be there
    assert await token_repository.is_blacklisted(future_token) is True


@pytest.mark.asyncio
async def test_token_repository_blacklist_long_token(test_db):
    """Test TokenRepository blacklist with very long token."""
    token_repository = TokenRepository(test_db)

    # Create a long token (but within database limits)
    long_token = "a" * 400  # 400 characters, should fit in VARCHAR(500)
    expires_at = datetime.utcnow() + timedelta(hours=1)

    # Blacklist long token
    blacklisted_token = await token_repository.blacklist(long_token, expires_at)

    assert blacklisted_token.token == long_token

    # Verify it's blacklisted
    is_blacklisted = await token_repository.is_blacklisted(long_token)
    assert is_blacklisted is True


@pytest.mark.asyncio
async def test_token_repository_blacklist_special_characters(test_db):
    """Test TokenRepository blacklist with special characters in token."""
    token_repository = TokenRepository(test_db)

    # Token with special characters (like a real JWT might have)
    special_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"  # noqa
    expires_at = datetime.utcnow() + timedelta(hours=1)

    # Blacklist token with special characters
    blacklisted_token = await token_repository.blacklist(special_token, expires_at)

    assert blacklisted_token.token == special_token

    # Verify it's blacklisted
    is_blacklisted = await token_repository.is_blacklisted(special_token)
    assert is_blacklisted is True


@pytest.mark.asyncio
async def test_token_repository_clean_mixed_expired_and_valid(test_db):
    """Test TokenRepository clean_expired_tokens with mixed expired and valid tokens."""
    token_repository = TokenRepository(test_db)

    current_time = datetime.utcnow()

    # Add expired tokens with different expiration times
    expired_tokens = []
    for i in range(3):
        token = f"expired_token_{i}"
        expires_at = current_time - timedelta(hours=i + 1)  # 1, 2, 3 hours ago
        await token_repository.blacklist(token, expires_at)
        expired_tokens.append(token)

    # Add valid tokens with different expiration times
    valid_tokens = []
    for i in range(2):
        token = f"valid_token_{i}"
        expires_at = current_time + timedelta(hours=i + 1)  # 1, 2 hours from now
        await token_repository.blacklist(token, expires_at)
        valid_tokens.append(token)

    # Clean expired tokens - no parameter needed
    cleaned_count = await token_repository.clean_expired_tokens()

    assert cleaned_count == 3  # Should clean 3 expired tokens

    # Verify expired tokens are gone
    for token in expired_tokens:
        assert await token_repository.is_blacklisted(token) is False

    # Verify valid tokens are still there
    for token in valid_tokens:
        assert await token_repository.is_blacklisted(token) is True


# Tests for TokenCleanupScheduler
@pytest.mark.asyncio
async def test_token_cleanup_scheduler_initialization():
    """Test TokenCleanupScheduler initialization."""
    scheduler = TokenCleanupScheduler()

    assert scheduler.scheduler is None
    assert scheduler.is_running is False
    assert scheduler.get_next_run_time() is None


@patch("app.repositories.token.AsyncIOScheduler")
def test_token_cleanup_scheduler_start(mock_scheduler_class):
    """Test TokenCleanupScheduler start method."""
    mock_scheduler = AsyncMock()
    mock_scheduler_class.return_value = mock_scheduler

    scheduler = TokenCleanupScheduler()
    scheduler.start_scheduler(interval_hours=2)

    assert scheduler.is_running is True
    mock_scheduler_class.assert_called_once()
    # The scheduler adds 2 jobs: token cleanup and session cleanup
    assert mock_scheduler.add_job.call_count == 2
    mock_scheduler.start.assert_called_once()


@patch("app.repositories.token.AsyncIOScheduler")
def test_token_cleanup_scheduler_stop(mock_scheduler_class):
    """Test TokenCleanupScheduler stop method."""
    mock_scheduler = AsyncMock()
    mock_scheduler_class.return_value = mock_scheduler

    scheduler = TokenCleanupScheduler()
    scheduler.start_scheduler()
    scheduler.stop_scheduler()

    assert scheduler.is_running is False
    mock_scheduler.shutdown.assert_called_once()


@patch("app.repositories.token.AsyncSessionLocal")
@pytest.mark.asyncio
async def test_token_cleanup_scheduler_cleanup_function(mock_session_local):
    """Test TokenCleanupScheduler cleanup function."""
    # Mock the session and repository
    mock_session = AsyncMock()
    mock_session_local.return_value.__aenter__.return_value = mock_session

    scheduler = TokenCleanupScheduler()

    # Mock TokenRepository methods
    with patch("app.repositories.token.TokenRepository") as mock_repo_class:
        mock_repo = AsyncMock()
        mock_repo.get_expired_token_count.return_value = 5
        mock_repo.clean_expired_tokens.return_value = 5
        mock_repo_class.return_value = mock_repo

        # Call the cleanup function directly
        await scheduler._cleanup_expired_tokens()

        # Verify the repository methods were called
        mock_repo.get_expired_token_count.assert_called_once()
        mock_repo.clean_expired_tokens.assert_called_once()
        mock_session.commit.assert_called_once()


@patch("app.repositories.token.AsyncSessionLocal")
@pytest.mark.asyncio
async def test_token_cleanup_scheduler_manual_cleanup(mock_session_local):
    """Test TokenCleanupScheduler manual cleanup method."""
    # Mock the session and repository
    mock_session = AsyncMock()
    mock_session_local.return_value.__aenter__.return_value = mock_session

    scheduler = TokenCleanupScheduler()

    # Mock TokenRepository methods
    with patch("app.repositories.token.TokenRepository") as mock_repo_class:
        mock_repo = AsyncMock()
        mock_repo.clean_expired_tokens.return_value = 3
        mock_repo_class.return_value = mock_repo

        # Call manual cleanup
        result = await scheduler.manual_cleanup()

        # Verify the result and calls
        assert result == 3
        mock_repo.clean_expired_tokens.assert_called_once()
        mock_session.commit.assert_called_once()


@pytest.mark.asyncio
async def test_token_cleanup_scheduler_start_already_running():
    """Test that starting an already running scheduler doesn't create issues."""
    with patch("app.repositories.token.AsyncIOScheduler") as mock_scheduler_class:
        mock_scheduler = AsyncMock()
        mock_scheduler_class.return_value = mock_scheduler

        scheduler = TokenCleanupScheduler()

        # Start scheduler twice
        scheduler.start_scheduler()
        scheduler.start_scheduler()  # Should not create a new scheduler

        # Should only be called once
        mock_scheduler_class.assert_called_once()
        mock_scheduler.start.assert_called_once()
