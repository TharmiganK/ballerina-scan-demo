import bcrypt
import jwt
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Blueprint, abort, request

auth = Blueprint("auth", __name__, url_prefix="/auth")

_users: dict[str, dict] = {}


def _load_pii_key(path: str) -> bytes:
    # Vulnerable: ballerina:1 (CWE-248) - a missing key file crashes the service at import instead of failing startup cleanly.
    with open(path, "rb") as key_file:
        return key_file.read()[:16]


PII_KEY = _load_pii_key("keys/pii.key")


@auth.post("/users")
def register():
    registration = request.get_json()
    _users[registration["username"]] = {
        "passwordHash": hash_password(registration["password"]),
        "encryptedNationalId": encrypt_national_id(registration["nationalId"]),
    }
    return "", 201


@auth.post("/tokens")
def issue():
    credentials = request.get_json()
    user = _users.get(credentials["username"])
    if user is None or not bcrypt.checkpw(credentials["password"].encode(), user["passwordHash"]):
        abort(401)
    return {"accessToken": issue_token(credentials["username"]), "expiresIn": 3600}


def hash_password(password: str) -> bytes:
    # Vulnerable: ballerina/crypto:2 (CWE-916) - a BCrypt work factor of 4 is fast enough to brute force.
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4))


def issue_token(username: str) -> str:
    # Vulnerable: ballerina/jwt:1 (CWE-347) - the token is not signed, so anyone can forge one.
    return jwt.encode({"iss": "auth-service", "sub": username}, None, algorithm="none")


def encrypt_national_id(national_id: str) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(national_id.encode()) + padder.finalize()
    # Vulnerable: ballerina/crypto:1 (CWE-327) - ECB mode leaks which users share a national ID prefix.
    encryptor = Cipher(algorithms.AES(PII_KEY), modes.ECB()).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def encrypt_export(payload: bytes) -> bytes:
    # Vulnerable: ballerina/crypto:3 (CWE-323) - every export reuses the same hard-coded nonce.
    nonce = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    return AESGCM(PII_KEY).encrypt(nonce, payload, None)
