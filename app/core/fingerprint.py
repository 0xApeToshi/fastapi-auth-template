import hashlib
from typing import Optional

from fastapi import Request


def generate_fingerprint(request: Request) -> str:
    """
    Generate a fingerprint based on request characteristics.
    Currently uses User-Agent only as per requirements.

    Args:
        request: FastAPI request object

    Returns:
        SHA256 hash of the fingerprint data
    """
    # Get User-Agent header
    user_agent = request.headers.get("User-Agent", "unknown")

    # Create fingerprint string
    fingerprint_data = f"ua:{user_agent}"

    # Return SHA256 hash
    return hashlib.sha256(fingerprint_data.encode()).hexdigest()


def verify_fingerprint(request: Request, stored_fingerprint: Optional[str]) -> bool:
    """
    Verify that the request fingerprint matches the stored one.

    Args:
        request: FastAPI request object
        stored_fingerprint: Previously stored fingerprint hash

    Returns:
        True if fingerprints match or no stored fingerprint
    """
    if not stored_fingerprint:
        return True

    current_fingerprint = generate_fingerprint(request)
    return current_fingerprint == stored_fingerprint


def get_client_ip(request: Request) -> str:
    """
    Get client IP address from request, handling proxies.

    Args:
        request: FastAPI request object

    Returns:
        Client IP address
    """
    # Check for forwarded IP (when behind proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP from the chain
        return forwarded_for.split(",")[0].strip()

    # Check for real IP header (some proxies use this)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip

    # Fall back to direct connection IP
    if request.client:
        return request.client.host

    return "unknown"
