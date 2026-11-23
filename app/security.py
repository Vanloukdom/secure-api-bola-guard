"""Authentification (JWT) et autorisation objet par objet."""
import logging
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass

import bcrypt
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from prometheus_client import Counter

from app.db import pool

SECRET = os.getenv("APP_SECRET", "dev-secret-change-me-dev-secret-change-me")
TOKEN_TTL = int(os.getenv("TOKEN_TTL_SECONDS", "900"))
log = logging.getLogger("authz")
DENIED = Counter("authz_denied_total", "Accès refusés (tentatives BOLA/IDOR)", ["resource"])
bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    id: int
    role: str

    @property
    def is_admin(self) -> bool:
        return self.role == "ADMIN"


def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()


def verify_password(pw: str, hashed: str) -> bool:
    return bcrypt.checkpw(pw.encode(), hashed.encode())


def issue_token(user_id: int) -> str:
    now = int(time.time())
    return jwt.encode({"sub": str(user_id), "iat": now, "exp": now + TOKEN_TTL}, SECRET, algorithm="HS256")


def current_principal(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    """L'identité vient UNIQUEMENT du token signé, jamais d'un paramètre client.
    Le rôle est relu en base : une rétrogradation est effective immédiatement."""
    if creds is None:
        raise HTTPException(401, "Authentification requise")
    try:
        claims = jwt.decode(creds.credentials, SECRET, algorithms=["HS256"], options={"require": ["exp", "sub"]})
    except jwt.PyJWTError:
        raise HTTPException(401, "Token invalide ou expiré")
    with pool.connection() as conn:
        row = conn.execute("SELECT id, role FROM users WHERE id = %s", (int(claims["sub"]),)).fetchone()
    if not row:
        raise HTTPException(401, "Utilisateur inconnu")
    return Principal(row["id"], row["role"])


def deny(resource: str, principal: Principal, target) -> HTTPException:
    DENIED.labels(resource).inc()
    log.warning("authz_denied resource=%s user=%s target=%s", resource, principal.id, target)
    # 404 et non 403 : on ne confirme pas l'existence de la ressource.
    return HTTPException(404, "Ressource introuvable")


@contextmanager
def scoped_connection(principal: Principal):
    """Connexion dont la session porte l'identité, pour la Row-Level Security."""
    with pool.connection() as conn:
        conn.execute("SET LOCAL ROLE app_rw")
        conn.execute("SELECT set_config('app.user_id', %s, true)", (str(principal.id),))
        conn.execute("SELECT set_config('app.user_role', %s, true)", (principal.role,))
        yield conn
