from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.db import close_db, init_db, pool
from app.observability import setup_observability
from app.security import (
    Principal, current_principal, deny, hash_password, issue_token, scoped_connection, verify_password,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    yield
    close_db()


app = FastAPI(
    title="Secure API — BOLA/IDOR guard",
    description="Autorisation au niveau objet : changer /users/125 en /users/126 ne sert à rien.",
    version="1.0.0",
    lifespan=lifespan,
)
setup_observability(app)

PUBLIC_USER = "id, email, full_name, phone, role"


class Credentials(BaseModel):
    email: str = Field(min_length=3)
    password: str = Field(min_length=8)


class UserPatch(BaseModel):
    # extra="forbid" : impossible d'envoyer {"role": "ADMIN"} (mass assignment).
    model_config = ConfigDict(extra="forbid")
    full_name: str | None = None
    phone: str | None = None


class DocumentIn(BaseModel):
    model_config = ConfigDict(extra="forbid")  # owner_id n'est jamais lu depuis le client
    title: str
    body: str = ""


@app.post("/auth/register", status_code=201)
def register(body: Credentials):
    with pool.connection() as conn:
        row = conn.execute(
            "INSERT INTO users (email, password_hash) VALUES (%s, %s) ON CONFLICT (email) DO NOTHING RETURNING id",
            (body.email.lower(), hash_password(body.password)),
        ).fetchone()
    if not row:
        raise HTTPException(409, "Email déjà utilisé")
    return {"id": row["id"]}


@app.post("/auth/login")
def login(body: Credentials):
    with pool.connection() as conn:
        row = conn.execute(
            "SELECT id, password_hash FROM users WHERE email = %s", (body.email.lower(),)
        ).fetchone()
    if not row or not verify_password(body.password, row["password_hash"]):
        raise HTTPException(401, "Identifiants invalides")
    return {"access_token": issue_token(row["id"]), "token_type": "bearer"}


@app.get("/api/me")
def me(p: Principal = Depends(current_principal)):
    return get_user(p.id, p)


@app.get("/api/users/{user_id}")
def get_user(user_id: int, p: Principal = Depends(current_principal)):
    if user_id != p.id and not p.is_admin:
        raise deny("user", p, user_id)
    with pool.connection() as conn:
        row = conn.execute(f"SELECT {PUBLIC_USER} FROM users WHERE id = %s", (user_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Ressource introuvable")
    return row


@app.patch("/api/users/{user_id}")
def patch_user(user_id: int, body: UserPatch, p: Principal = Depends(current_principal)):
    if user_id != p.id and not p.is_admin:
        raise deny("user", p, user_id)
    fields = body.model_dump(exclude_unset=True)
    if not fields:
        return get_user(user_id, p)
    sets = ", ".join(f"{k} = %({k})s" for k in fields)  # clés issues du modèle, pas du client
    with pool.connection() as conn:
        return conn.execute(
            f"UPDATE users SET {sets} WHERE id = %(id)s RETURNING {PUBLIC_USER}", {**fields, "id": user_id}
        ).fetchone()


@app.post("/api/documents", status_code=201)
def create_document(body: DocumentIn, p: Principal = Depends(current_principal)):
    with scoped_connection(p) as conn:
        return conn.execute(
            "INSERT INTO documents (owner_id, title, body) VALUES (%s, %s, %s) RETURNING *",
            (p.id, body.title, body.body),
        ).fetchone()


@app.get("/api/documents")
def list_documents(p: Principal = Depends(current_principal)):
    with scoped_connection(p) as conn:
        return conn.execute(
            "SELECT * FROM documents WHERE owner_id = %s ORDER BY id", (p.id,)
        ).fetchall()


@app.get("/api/documents/{doc_id}")
def get_document(doc_id: int, p: Principal = Depends(current_principal)):
    # Couche 1 : la requête est filtrée par propriétaire. Couche 2 : RLS.
    with scoped_connection(p) as conn:
        row = conn.execute(
            "SELECT * FROM documents WHERE id = %s AND (owner_id = %s OR %s)", (doc_id, p.id, p.is_admin)
        ).fetchone()
    if not row:
        raise deny("document", p, doc_id)
    return row


@app.delete("/api/documents/{doc_id}", status_code=204)
def delete_document(doc_id: int, p: Principal = Depends(current_principal)):
    with scoped_connection(p) as conn:
        deleted = conn.execute(
            "DELETE FROM documents WHERE id = %s AND owner_id = %s RETURNING id", (doc_id, p.id)
        ).fetchone()
    if not deleted:
        raise deny("document", p, doc_id)
