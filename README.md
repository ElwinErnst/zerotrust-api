# Sentinel Suite ZeroTrust Gateway

Gateway Zero Trust entre clientes y servicios internos.

## Responsabilidades

Para cada request:

1. valida el JWT emitido por `auth-api`
2. evalúa políticas por upstream, path, método y rol
3. firma la request downstream con HMAC
4. reenvía el contexto autenticado a `vault-api`

## Flujo actual

```text
Client
  -> zerotrust-api
  -> vault-api
```

`zerotrust-api` confía en:

- JWT emitido por `auth-api`

`vault-api` confía en:

- firma Zero Trust
- timestamp + nonce
- contexto de usuario/tenant que llega firmado

## Integración vigente

El flujo validado hoy es:

1. login en `auth-api`
2. request a `zerotrust-api`
3. `zerotrust-api` valida el JWT
4. `zerotrust-api` aplica policy
5. `zerotrust-api` firma la request
6. `vault-api` verifica firma y procesa la operación

## Headers Zero Trust

El gateway agrega headers como:

- `x-zt-v`
- `x-zt-user-id`
- `x-zt-tenant-id`
- `x-zt-roles`
- `x-zt-ts`
- `x-zt-nonce`
- `x-zt-body-sha256`
- `x-zt-sig`

## Policies

Las políticas locales viven en:

- `local/policies.json`

Hoy el upstream activo del stack es `vault`.

## Canonical request y firma

La request se firma con `HMAC-SHA256` sobre una representación canónica que incluye:

- método
- path
- query
- hash del body
- user id
- tenant id
- roles
- timestamp
- nonce

Eso protege contra:

- spoofing de headers
- tampering de request
- replay attacks
- bypass del gateway

## Setup local

```bash
yarn install
yarn start:dev
```

Con Docker, el servicio queda accesible en:

- [http://localhost:3010](http://localhost:3010)

## Ejemplo

Listado de tenants a través del gateway:

```bash
curl http://localhost:3010/vault/tenants \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

## Notas

- `OWNER` satisface políticas que requieran `ADMIN` o `MEMBER`
- el gateway expone `vault-api` bajo el prefijo `/vault`
- la firma HMAC y el JWT usan secretos distintos
