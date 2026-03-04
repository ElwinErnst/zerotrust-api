# SentinelSuite – ZeroTrust Gateway

## Introducción

Este proyecto implementa un **Zero Trust Gateway** para proteger múltiples servicios internos.

El principio de Zero Trust es:

> Never trust, always verify.

Esto significa que **ninguna request se considera confiable por defecto**, incluso si proviene de dentro del sistema.

Cada request debe verificarse antes de acceder a un servicio.

---

## Problema que resuelve

En una arquitectura tradicional:

```
Client → Service
```

Los servicios confían en:

- headers
- IP interna
- red privada

Esto permite ataques como:

- bypass del gateway
- falsificación de headers
- modificación de requests
- replay attacks

El ZeroTrust Gateway evita estos problemas.

---

## Arquitectura del sistema

```
                ┌──────────────┐
                │   Client     │
                │ (Web / API)  │
                └──────┬───────┘
                       │
                       │ HTTPS
                       ▼
               ┌─────────────────┐
               │ ZeroTrust GW    │
               │ (NestJS)        │
               │                 │
               │ 1. Verify JWT   │
               │ 2. Policy check │
               │ 3. Sign request │
               └──────┬──────────┘
                      │
                      │ signed request
                      ▼
       ┌───────────────────────────────┐
       │        Upstream Services      │
       │                               │
       │  Vault API                    │
       │  Payments API                 │
       │  Notary API                   │
       │                               │
       │  Verify ZT Signature          │
       │  Validate nonce               │
       └───────────────────────────────┘
```

El gateway actúa como **portero de seguridad**.

---

# Flujo de una request

## 1. Cliente llama al gateway

Ejemplo:

```
POST /vault/documents
Authorization: Bearer <JWT>
```

---

## 2. Gateway valida el usuario

El gateway valida el JWT y obtiene:

- userId
- tenantId
- roles

---

## 3. Policy Engine

El gateway evalúa las políticas de acceso.

Ejemplo:

- ADMIN → puede subir documentos
- MEMBER → solo puede leer

Si no cumple la política:

```
403 Forbidden
```

---

## 4. Firma de request

El gateway firma la request antes de enviarla al servicio downstream.

Se agregan headers:

- `x-zt-v`
- `x-zt-user-id`
- `x-zt-tenant-id`
- `x-zt-roles`
- `x-zt-ts`
- `x-zt-nonce`
- `x-zt-body-sha256`
- `x-zt-sig`

---

# Canonical Request

Antes de generar la firma se construye una **canonical request**.

Ejemplo:

```text
v:1
method:POST
path:/documents
query:vaultId=123
body_sha256:abc123...
user_id:1
tenant_id:1
roles:ADMIN
ts:1710000000
nonce:550e8400-e29b-41d4-a716-446655440000
```

Esto evita que alguien modifique partes de la request.

---

# Firma HMAC

La firma se calcula usando HMAC-SHA256.

```
signature = HMAC(secret, canonical_request)
```

Solo dos componentes conocen el secreto:

- Gateway
- Servicios internos

---

# Verificación en el servicio downstream

Cuando el servicio recibe la request:

1. reconstruye canonical request
2. recalcula la firma
3. compara con `x-zt-sig`

Si la firma no coincide:

```
403 Invalid Signature
```

---

# Protección contra Replay Attacks

Cada request incluye:

- `x-zt-ts`
- `x-zt-nonce`

El sistema guarda temporalmente los nonce usados.

Si un nonce se repite:

```
Replay attack detected
```

---

# Seguridad que aporta el sistema

| Ataque | Protección |
|------|------|
| Header spoofing | Firma HMAC |
| Tampering de request | Canonical request |
| Modificación de body | SHA256 |
| Replay attack | Nonce store |
| Bypass del gateway | Verificación ZT |
| Escalación de privilegios | Policy engine |

---

# Estructura del proyecto

```
src
├ common
│ ├ crypto
│ │ ├ canonical.ts
│ │ └ hmac-signer.ts
│ │
│ └ zt
│   ├ zt-verify.ts
│   └ nonce-store.ts
│
├ modules
│ ├ gateway
│ ├ auth
│ └ policy
│
└ config
  ├ jwt.config.ts
  ├ upstreams.config.ts
  └ zt.config.ts
```

---

# Componentes

## Gateway

Responsable de:

- validar JWT
- aplicar políticas
- firmar requests
- proxy a servicios

---

## Auth Module

Valida tokens JWT.

Archivo principal:

```
jwt-verify.service.ts
```

---

## Policy Engine

Define reglas de acceso.

Ejemplo:

- ADMIN → write
- MEMBER → read

---

## Crypto

### canonical.ts

Genera la canonical request.

### hmac-signer.ts

Genera la firma HMAC.

---

## ZeroTrust Verification

### zt-verify.ts

Valida los headers firmados.

### nonce-store.ts

Previene replay attacks.

---

# Ejemplo de request real

Cliente:

```
POST /vault/documents
```

Gateway agrega:

```
x-zt-user-id: 123
x-zt-tenant-id: tenantA
x-zt-roles: ADMIN
x-zt-ts: 1710000000
x-zt-nonce: 550e8400-e29b-41d4-a716-446655440000
x-zt-body-sha256: abc123...
x-zt-sig: 92fd21...
```

El servicio downstream verifica la firma antes de procesar la request.

---

# Roadmap

Próximos pasos del proyecto:

1. Policy engine configurable (`policies.yaml`)
2. Admin UI (Electron)
3. Redis nonce store
4. Rate limiting
5. mTLS interno

---

# Tecnologías

- Node.js
- NestJS
- HMAC-SHA256
- JWT
- Zero Trust Architecture

---

# Licencia

MIT
