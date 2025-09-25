"""
PKCE (Proof Key for Code Exchange) utilities for OAuth2
Implements RFC 7636 - Proof Key for Code Exchange by OAuth Public Clients
"""
import base64
import hashlib
import os


def generate_code_verifier() -> str:
    """
    Generate a random code verifier for PKCE
    :return: A random string of 43-128 characters
    """
    # Generate 32 bytes of random data
    verifier_bytes = os.urandom(32)
    # Encode using base64url encoding
    return base64.urlsafe_b64encode(verifier_bytes).decode('utf-8').rstrip('=')


def generate_code_challenge(code_verifier: str) -> str:
    """
    Generate a code challenge from a code verifier using SHA-256
    :param code_verifier: The code verifier string
    :return: The code challenge string
    """
    # Hash the code verifier using SHA-256
    hashed = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    # Encode using base64url encoding
    return base64.urlsafe_b64encode(hashed).decode('utf-8').rstrip('=')


def generate_pkce_pair() -> dict:
    """
    Generate PKCE code verifier and challenge pair
    :return: Dictionary containing code_verifier and code_challenge
    """
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge
    }
