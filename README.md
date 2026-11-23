# Le compte d'un autre — sécurité (BOLA/IDOR)

[![ci-cd](https://github.com/Vanloukdom/secure-api-bola-guard/actions/workflows/ci-cd.yml/badge.svg)](https://github.com/Vanloukdom/secure-api-bola-guard/actions/workflows/ci-cd.yml)
![Python](https://img.shields.io/badge/Python-3.12-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688) ![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791) ![k3s](https://img.shields.io/badge/k3s-deploy-FFC61C)

> Projet **05/10** de la série *« 10 problèmes que tout ingénieur logiciel devrait savoir résoudre »*.
> Démo : `https://bola.apps.vansoreldatacloud.com` · Documentation interactive : `https://bola.apps.vansoreldatacloud.com/docs`


## Le problème

Un utilisateur authentifié remplace `/api/users/125` par `/api/users/126` et lit les données privées d'un autre. C'est **BOLA/IDOR**, risque n°1 du **Top 10 OWASP API Security**. Comment l'empêcher définitivement, même si l'attaquant manipule toutes les requêtes ?

## La solution

- **L'identité vient uniquement du JWT signé** (`sub`), jamais d'un paramètre, d'un corps ou d'un en-tête envoyé par le client.
- **Contrôle objet par objet** à chaque requête : `WHERE id = ? AND owner_id = :utilisateur_du_token`.
- **Défense en profondeur avec la Row-Level Security PostgreSQL** (`FORCE ROW LEVEL SECURITY`, rôle `app_rw`) : même une requête « oubliée » sans filtre ne renvoie que les lignes de l'utilisateur.
- **Mass assignment bloqué** : modèles Pydantic `extra="forbid"`. Envoyer `{"role":"ADMIN"}` ou `owner_id` → `422`.
- **404 plutôt que 403** : on ne confirme pas l'existence d'une ressource.
- Rôle **relu en base** à chaque requête : une rétrogradation est immédiate.
- Métrique **`authz_denied_total`** et logs pour détecter l'énumération d'identifiants (alerte Grafana).
- Les ID restent **séquentiels exprès** : la sécurité ne repose pas sur des ID impossibles à deviner.

## Architecture

```mermaid
flowchart LR
    R[GET /api/documents/126 + JWT] --> A[Vérif. signature JWT]
    A --> P[Principal = sub du token]
    P --> Q[SQL WHERE id=126 AND owner_id=principal]
    Q --> RLS[RLS PostgreSQL : 2e barrière]
    RLS -- vide --> D[404 + authz_denied_total++]
    RLS -- ligne --> OK[200]
```

## API

| Méthode | Route | Rôle |
|---|---|---|
| POST | `/auth/register`, `/auth/login` | Compte et JWT |
| GET | `/api/me` | Mon profil |
| GET/PATCH | `/api/users/{id}` | Profil (soi-même ou admin) |
| POST/GET | `/api/documents` | Mes documents |
| GET/DELETE | `/api/documents/{id}` | Un document (propriétaire uniquement) |

### Démo

```bash
URL=https://bola.apps.vansoreldatacloud.com
TOKEN=$(curl -s -XPOST $URL/auth/login -H 'content-type: application/json' \
  -d '{"email":"alice@ex.com","password":"S3cure-pass!"}' | jq -r .access_token)
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN" $URL/api/users/126   # 404
```

## Lancer en local

```bash
docker compose up --build          # API sur http://localhost:8000/docs
```

## Tests

```bash
docker compose up -d db
pip install -r requirements.txt -r requirements-dev.txt
ADMIN_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres pytest -q
```

Ce qui est prouvé : Lecture du profil voisin → 404 ; élévation de rôle par mass assignment → 422 ; documents isolés ; RLS efficace même avec une requête non filtrée ; JWT forgé → 401.

## Déploiement en production (k3s sur VPS)

Pipeline GitHub Actions `test → build → deploy` :

1. **test** : pytest avec PostgreSQL en service ;
2. **build** : image multi-couches poussée sur `ghcr.io/vanloukdom/secure-api-bola-guard` (tags `sha` et `latest`) ;
3. **deploy** : `kubectl apply -k k8s/` dans le namespace `p05-bola`, puis attente du `rollout status`.

Secrets à créer dans *Settings → Secrets and variables → Actions* :

| Secret | Contenu |
|---|---|
| `KUBECONFIG_B64` | `base64 -w0 kubeconfig` du cluster k3s (sans ce secret, l'étape deploy est ignorée) |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL (fixe : ne pas le changer après le premier déploiement) |
| `APP_SECRET` | `openssl rand -hex 32` |

Côté cluster : Traefik (inclus dans k3s), cert-manager avec un `ClusterIssuer` `letsencrypt-prod`, un enregistrement DNS `*.apps.vansoreldatacloud.com` vers le VPS, et le package GHCR passé en **public** (ou un `imagePullSecret`).

Sécurité des pods : utilisateur non root, système de fichiers en lecture seule, capabilities supprimées, requests/limits, probes `/healthz` et `/readyz`, métriques Prometheus sur `/metrics`.

## Pour aller plus loin

OPA/Cedar pour des politiques complexes ; rotation des clés (RS256 + JWKS) ; tests DAST (OWASP ZAP) dans la CI.

---
Van Sorel LOUKDOM · DevOps / Cloud & Data Engineer · Licence MIT
