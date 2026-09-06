"""Strict, offline OAuth access-token verification for the optional team gateway.

No discovery or attacker-selected URL fetches. Operators supply and rotate a local
public JWKS. This is an RS256 access-token resource server, not an OIDC login client.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .util import TapeoutError, ensure, loads, read_json


class TeamError(TapeoutError):
    def __init__(self, code: str, message: str, status: int = 422):
        super().__init__(message)
        self.code, self.status = code, status


def require(condition: bool, code: str, message: str, status: int = 422) -> None:
    if not condition:
        raise TeamError(code, message, status)


@dataclass(frozen=True)
class Identity:
    issuer: str
    subject: str
    client_id: str
    scopes: frozenset[str]
    expires: int


class AccessTokens:
    def __init__(self, config: dict):
        ensure(isinstance(config, dict) and set(config) == {
            "issuer", "audience", "jwks_file", "client_ids", "max_lifetime_seconds"},
            "Invalid access-token configuration")
        parsed = urlsplit(config["issuer"])
        ensure(parsed.scheme == "https" and parsed.hostname and not parsed.username
               and not parsed.password and not parsed.query and not parsed.fragment, "HTTPS issuer required")
        ensure(isinstance(config["audience"], str) and 0 < len(config["audience"]) <= 512, "Audience required")
        clients = config["client_ids"]
        ensure(isinstance(clients, list) and clients and all(isinstance(c, str) and c for c in clients)
               and len(clients) == len(set(clients)), "Explicit client allowlist required")
        limit = config["max_lifetime_seconds"]
        ensure(type(limit) is int and 1 <= limit <= 3600, "Token lifetime must be 1..3600 seconds")
        self.config = config
        self.path = Path(config["jwks_file"])
        ensure(self.path.is_absolute(), "JWKS path must be absolute")
        self.keys()  # Validate operator configuration before serving.

    def keys(self) -> dict:
        import jwt
        ensure(not self.path.is_symlink(), "JWKS must not be a symlink")
        data = read_json(self.path)
        ensure(isinstance(data, dict) and set(data) == {"keys"} and isinstance(data["keys"], list)
               and 1 <= len(data["keys"]) <= 32, "Invalid public JWKS")
        keys = {}
        for entry in data["keys"]:
            ensure(isinstance(entry, dict) and entry.get("kty") == "RSA"
                   and entry.get("use") == "sig" and entry.get("alg") == "RS256"
                   and not set(entry) & {"d", "p", "q", "dp", "dq", "qi", "oth"}, "Public RS256 signing keys required")
            kid = entry.get("kid")
            ensure(isinstance(kid, str) and 0 < len(kid) <= 128 and kid not in keys, "Missing or duplicate JWKS key ID")
            ensure(entry.get("key_ops", ["verify"]) == ["verify"], "JWKS key cannot be used for verification")
            try:
                key = jwt.PyJWK.from_dict(entry, algorithm="RS256").key
                ensure(key.key_size >= 2048, "RSA key must be at least 2048 bits")
            except (jwt.PyJWTError, ValueError, TypeError, KeyError) as exc:
                raise TapeoutError("Invalid public RSA key") from exc
            keys[kid] = key
        return keys

    def verify(self, token: str) -> Identity:
        import jwt
        try:
            require(isinstance(token, str) and 0 < len(token) <= 16384, "AUTHENTICATION", "Invalid access token", 401)
            parts = token.split(".")
            ensure(len(parts) == 3, "Invalid JWT")
            # Reject duplicate JSON keys before the library's ordinary JSON decoder.
            decoded = []
            for part in parts[:2]:
                ensure(part and all(c.isascii() and (c.isalnum() or c in "-_") for c in part), "Invalid JWT encoding")
                decoded.append(loads(base64.b64decode(part + "=" * (-len(part) % 4), altchars=b"-_", validate=True)))
            header, untrusted = decoded
            ensure(isinstance(header, dict) and isinstance(untrusted, dict), "Invalid JWT objects")
            ensure(set(header) <= {"alg", "typ", "kid"} and header.get("alg") == "RS256"
                   and str(header.get("typ", "")).lower() in {"at+jwt", "application/at+jwt"}, "Access token type required")
            kid = header.get("kid")
            ensure(isinstance(kid, str), "JWT key ID required")
            keys = self.keys()  # Reload: removed/rotated keys take effect without restart.
            ensure(kid in keys, "Unknown JWT signing key")
            claims = jwt.decode(token, keys[kid], algorithms=["RS256"], issuer=self.config["issuer"],
                                audience=self.config["audience"], leeway=0,
                                options={"require": ["iss", "sub", "aud", "exp", "iat", "jti", "client_id"]})
            ensure(all(type(claims[k]) is int for k in ("iat", "exp")), "Integer token dates required")
            ensure("nbf" not in claims or type(claims["nbf"]) is int, "Integer not-before required")
            ensure(0 < claims["exp"] - claims["iat"] <= self.config["max_lifetime_seconds"], "Excessive token lifetime")
            ensure(all(isinstance(claims[k], str) and 0 < len(claims[k]) <= 512
                       for k in ("sub", "jti", "client_id")), "Token identity required")
            ensure(claims["client_id"] in self.config["client_ids"], "Client not allowed")
            scope = claims.get("scope", "")
            ensure(isinstance(scope, str) and len(scope) <= 4096, "Invalid token scope")
            return Identity(claims["iss"], claims["sub"], claims["client_id"],
                            frozenset(scope.split()), claims["exp"])
        except (jwt.PyJWTError, TapeoutError, ValueError, TypeError, KeyError, OSError) as exc:
            # Never echo tokens, claims, path names, or signature diagnostics to unauthenticated clients.
            raise TeamError("AUTHENTICATION", "A valid authorized access token is required", 401) from exc
