# Sytadel ZeroTrust Gateway

Gateway de enforcement de políticas Zero Trust entre clientes y servicios internos.

## Qué es (individual)

`zerotrust-api` es un **gateway de autorización** que se pone delante de tus servicios internos. Por cada request:

1. valida el JWT del cliente (emitido por un IdP en el que confía)
2. evalúa políticas por upstream, path, método y rol del tenant
3. firma la request hacia el downstream (canonical request + firma)
4. reenvía el contexto autenticado ya verificado

Es reutilizable fuera de Sytadel: apuntás `VAULT_BASE_URL` (o el upstream que quieras proteger) a tu propio servicio, le das un issuer/secreto de JWT, y obtenés enforcement de políticas por tenant + firma S2S anti-replay delante de cualquier API. Incluye un compilador **NL → RBAC** (Claude emite un `PolicySet` que un evaluador determinista aplica en runtime).

## Rol en Sytadel

Es el **perímetro obligatorio** de la suite: ningún cliente habla directo con `vault-api`. El gateway valida el JWT de `auth-api`, resuelve la política del tenant y firma la llamada al vault. Expone `vault-api` bajo el prefijo `/vault`.

```text
Client --JWT--> zerotrust-api --signed S2S--> vault-api
                     |
                     +-- valida JWT / resuelve directorio --> auth-api
```

Ver la [arquitectura de la suite](../../README.md).

## Firma y anti-replay

La request se firma con `HMAC-SHA256` sobre una representación canónica: método, path, query, hash del body, user id, tenant id, roles, timestamp y nonce. Eso protege contra spoofing de headers, tampering, replay y bypass del gateway.

> **Roadmap:** hay firma asimétrica Ed25519 (`ZT_SIGN_MODE`) implementada para reemplazar el HMAC compartido con el vault; **HMAC sigue siendo el default en runtime** (`ZT_ACCEPT_V1_HMAC=true`).

## Headers Zero Trust

El gateway agrega: `x-zt-v`, `x-zt-user-id`, `x-zt-tenant-id`, `x-zt-roles`, `x-zt-ts`, `x-zt-nonce`, `x-zt-body-sha256`, `x-zt-sig`.

## Policies

Las políticas locales viven en `local/policies.json` (`ZT_POLICIES_FILE`). Hoy el upstream activo del stack es `vault`.

## Uso standalone

```bash
yarn install
yarn start:dev        # http://localhost:3010
```

Requisitos mínimos:

- un emisor de JWT en el que confiar (`ZT_JWT_ISSUER`, `ZT_JWT_AUDIENCE`, `ZT_JWT_HS256_SECRET`)
- un directorio de identidad para resolver tenants/memberships (`AUTH_DIRECTORY_BASE_URL`) — puede ser `auth-api` u otro compatible
- el upstream a proteger (`VAULT_BASE_URL`)
- PostgreSQL para el store anti-replay

Ejemplo a través del gateway:

```bash
curl http://localhost:3010/vault/tenants -H "Authorization: Bearer <ACCESS_TOKEN>"
```

## Uso en la suite

Desde la raíz del meta-repo, `docker compose up --build`. En la red interna alcanza `auth-api` en `http://auth-api:3001/api` y `vault-api` en `http://vault-api:3000`; se publica al host en `http://localhost:3010`.

## Notas

- `OWNER` satisface políticas que requieran `ADMIN` o `MEMBER`
- el gateway expone `vault-api` bajo el prefijo `/vault`
- la firma HMAC y el JWT usan secretos distintos

## Licencia

Apache-2.0. Ver [LICENSE](./LICENSE).
