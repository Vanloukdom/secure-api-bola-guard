import uuid

from app.db import pool
from app.security import Principal, scoped_connection


def _user(client):
    email = f"{uuid.uuid4().hex[:8]}@example.com"
    uid = client.post("/auth/register", json={"email": email, "password": "S3cure-pass!"}).json()["id"]
    token = client.post("/auth/login", json={"email": email, "password": "S3cure-pass!"}).json()["access_token"]
    return uid, {"Authorization": f"Bearer {token}"}


def test_cannot_read_neighbour_profile(client):
    alice_id, alice = _user(client)
    bob_id, _ = _user(client)
    assert client.get(f"/api/users/{alice_id}", headers=alice).status_code == 200
    assert client.get(f"/api/users/{bob_id}", headers=alice).status_code == 404
    assert client.get(f"/api/users/{bob_id}").status_code == 401


def test_cannot_escalate_role_by_mass_assignment(client):
    alice_id, alice = _user(client)
    r = client.patch(f"/api/users/{alice_id}", json={"role": "ADMIN"}, headers=alice)
    assert r.status_code == 422
    assert client.get("/api/me", headers=alice).json()["role"] == "USER"


def test_documents_are_isolated(client):
    _, alice = _user(client)
    _, bob = _user(client)
    doc = client.post("/api/documents", json={"title": "Fiche de paie"}, headers=alice).json()
    assert client.get(f"/api/documents/{doc['id']}", headers=bob).status_code == 404
    assert client.delete(f"/api/documents/{doc['id']}", headers=bob).status_code == 404
    assert client.get(f"/api/documents/{doc['id']}", headers=alice).status_code == 200
    # Impossible de créer un document au nom d'un autre
    assert client.post("/api/documents", json={"title": "x", "owner_id": 1}, headers=bob).status_code == 422


def test_rls_protects_even_a_buggy_unscoped_query(client):
    alice_id, alice = _user(client)
    bob_id, _ = _user(client)
    client.post("/api/documents", json={"title": "Secret d'Alice"}, headers=alice)
    with scoped_connection(Principal(bob_id, "USER")) as conn:
        # Requête « oubliée » sans filtre owner_id : la base ne renvoie rien d'Alice.
        rows = conn.execute("SELECT * FROM documents").fetchall()
    assert all(r["owner_id"] == bob_id for r in rows)


def test_admin_can_read_users(client):
    admin_id, admin = _user(client)
    bob_id, _ = _user(client)
    with pool.connection() as conn:
        conn.execute("UPDATE users SET role = 'ADMIN' WHERE id = %s", (admin_id,))
    assert client.get(f"/api/users/{bob_id}", headers=admin).status_code == 200


def test_forged_token_rejected(client):
    import jwt
    forged = jwt.encode({"sub": "1", "exp": 9999999999}, "wrong-secret", algorithm="HS256")
    assert client.get("/api/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401
