# 📜 Contrato Formal de API REST & Especificación Zero-Trust

**Versión de la API:** 1.0.0  
**Prefijo Base:** `/api/v1`  
**Estándar de Errores:** RFC 7807 (Problem Details for HTTP APIs)  
**Formato de Intercambio:** `application/json`  
**Zona Horaria por Defecto:** `America/Mexico_City` (GMT-6)

---

## 🏛️ 1. Normativa General y Encabezados Globales

Todas las peticiones a la API deben cumplir con las siguientes directivas de ciberseguridad y trazabilidad:

### Encabezados de Respuesta Obligatorios (Inyectados por Middleware):
- `X-Request-ID`: Identificador único UUIDv4 para correlación distribuida en registros SIEM.
- `X-Process-Time-Ms`: Tiempo exacto de procesamiento del servidor en milisegundos.
- `Content-Security-Policy`: Restricción estricta de fuentes de ejecución script y conexiones.
- `Strict-Transport-Security`: `max-age=31536000; includeSubDomains` (En entornos HTTPS).
- `X-Content-Type-Options`: `nosniff`
- `X-Frame-Options`: `DENY`

---

## 🚨 2. Estándar de Manejo de Errores (RFC 7807)

Cualquier error devuelto por la API con código de estado HTTP 4xx o 5xx sigue la estructura normalizada **RFC 7807**:

```json
{
  "type": "https://errors.enterprise-otp.io/v1/invalid-pow-nonce",
  "title": "Invalid Proof-of-Work Nonce",
  "status": 400,
  "detail": "The provided PoW nonce does not satisfy the required SHA-256 target difficulty prefix.",
  "instance": "/api/v1/auth/request-otp"
}
```

---

## 🔑 3. Endpoints Criptográficos y Autenticación

### 3.1 `GET /api/v1/auth/pow-challenge`
Solicita un desafío de Prueba de Trabajo (Proof-of-Work) SHA-256 para mitigar ataques de fuerza bruta y botnets sin captchas.

- **Autenticación:** Pública.
- **Respuesta 200 OK:**
```json
{
  "challenge_id": "04b26d6a-faea-497c-9f69-7ed4a28fcee9",
  "challenge_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "difficulty_bits": 12,
  "expires_in_seconds": 120
}
```

---

### 3.2 `POST /api/v1/auth/request-otp`
Evalúa los 7 vectores contextuales del cliente (RBA Engine), determina la entropía requerida y despacha el código OTP.

- **Autenticación:** Pública (Requiere Token PoW y Nonce resuelto).
- **Cuerpo de la Petición (Request Body):**
```json
{
  "email": "jmacias@upchiapas.edu.mx",
  "pow_challenge_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "pow_nonce": "4002",
  "is_new_device": false,
  "geo_velocity_alert": false
}
```
- **Respuesta 200 OK:**
```json
{
  "message": "OTP verification code sent successfully.",
  "expires_in_seconds": 300,
  "risk_level": "low",
  "risk_score": 0.0,
  "risk_factors": [],
  "entropy_bits": 19.93,
  "otp_length": 6,
  "otp_type": "numeric"
}
```
- **Errores Posibles:** `400 Bad Request` (PoW Inválido/Expirado), `429 Too Many Requests` (Límite >3 req/min).

---

### 3.3 `POST /api/v1/auth/verify-otp`
Verifica el código OTP ingresado por el usuario y emite el par de Tokens JWT con rastreo de familia de sesión DAG.

- **Autenticación:** Pública.
- **Cuerpo de la Petición (Request Body):**
```json
{
  "email": "jmacias@upchiapas.edu.mx",
  "code": "334030"
}
```
- **Respuesta 200 OK:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in_seconds": 900
}
```
- **Errores Posibles:** `401 Unauthorized` (Código OTP incorrecto o expirado), `429 Lockout` (3 intentos fallidos consecutivos).

---

### 3.4 `POST /api/v1/auth/refresh`
Rota el Refresh Token actual por uno nuevo. Detecta la reutilización de tokens ya consumidos en el Grafo DAG y revoca inmediatamente toda la familia de tokens en $<0.1\text{ ms}$.

- **Autenticación:** Pública (Requiere Refresh Token válido).
- **Cuerpo de la Petición (Request Body):**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```
- **Respuesta 200 OK (Rotación Exitosa):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in_seconds": 900
}
```
- **Respuesta 401 Unauthorized (Brecha / Reuso Detectado):**
```json
{
  "type": "https://errors.enterprise-otp.io/v1/token-reuse-revocation",
  "title": "Security Violation: Refresh Token Reuse Detected",
  "status": 401,
  "detail": "Revocación en cascada ejecutada. Toda la familia de tokens asociada a la sesión ha sido invalidada inmediatamente.",
  "instance": "/api/v1/auth/refresh"
---

### 3.5 `POST /api/v1/auth/webauthn/*`
Rutas de autenticación biométrica hardware W3C WebAuthn / Passkeys (FIDO2).

- **`POST /api/v1/auth/webauthn/register-options`:** Genera el desafío de registro biométrico.
- **`POST /api/v1/auth/webauthn/register-verify`:** Verifica y almacena la clave pública del autenticador.
- **`POST /api/v1/auth/webauthn/authenticate-options`:** Genera el desafío de firma para inicio de sesión.
- **`POST /api/v1/auth/webauthn/authenticate-verify`:** Verifica la firma biométrica y emite la sesión de tokens JWT con seguimiento en el Grafo DAG.

---

## 👤 4. Usuarios y Administración RBAC

### 4.1 `GET /api/v1/users/me`
Retorna el perfil del usuario autenticado.

- **Autenticación:** Requerida (`Authorization: Bearer <access_token>`).
- **Respuesta 200 OK:**
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "jmacias@upchiapas.edu.mx",
  "roles": ["user"],
  "is_active": true,
  "created_at": "2026-08-18T15:00:00-06:00"
}
```

---

### 4.2 `POST /api/v1/admin/users`
Creación individual de usuarios por parte de un administrador.

- **Autenticación:** Requerida (`Bearer Token` con Rol `admin` y Permiso `admin:write`).
- **Cuerpo de la Petición (Request Body):**
```json
{
  "email": "nuevo.usuario@upchiapas.edu.mx",
  "password": "PasswordSeguro123!",
  "role_name": "user",
  "phone_number": "+529610001122",
  "is_verified": true
}
```
- **Respuesta 201 Created:** Retorna la entidad del usuario creado.

---

### 4.3 `GET /api/v1/admin/users`
Consulta la lista completa de usuarios registrados.

- **Autenticación:** Requerida (`Bearer Token` con Rol `admin` y Permiso `admin:read`).
- **Respuesta 200 OK:** Array de objetos de usuarios con sus roles y permisos.

---

### 4.4 `DELETE /api/v1/admin/users/{user_id}`
Eliminación permanente e individual de un usuario por su identificador UUID.

- **Autenticación:** Requerida (`Bearer Token` con Rol `admin` y Permiso `admin:write`).
- **Restricción:** No se permite que el administrador elimine su propia cuenta activa.
- **Respuesta 200 OK:**
```json
{
  "message": "User 'usuario@ejemplo.com' with ID '763d603c-b3d5-419b-a911-29a1b950b747' has been permanently deleted.",
  "deleted_user_id": "763d603c-b3d5-419b-a911-29a1b950b747",
  "deleted_email": "usuario@ejemplo.com"
}
```
- **Respuesta 404 Not Found:** Si el `user_id` no existe en la base de datos.

---

### 4.5 `POST /api/v1/admin/users/upload-csv`
Población masiva de usuarios en el sistema mediante la carga de un archivo `.csv`.

- **Autenticación:** Requerida (`Bearer Token` con Rol `admin` y Permiso `admin:write`).
- **Formato del Cuerpo (Multipart Form):** `file` (`UploadFile` con extensión `.csv`).

#### 📑 Estructura y Formato del Archivo CSV:
El archivo CSV debe incluir los siguientes encabezados obligatorios en la primera línea:
```csv
email,password,role,phone_number
juan.perez@upchiapas.edu.mx,SecurePass123!,user,+529611234567
maria.gomez@upchiapas.edu.mx,AdminSecret2026!,admin,+529619876543
carlos.diaz@upchiapas.edu.mx,,user,
```

#### Especificación de Campos del CSV:
- **`email`** *(Obligatorio)*: Correo electrónico único del usuario.
- **`password`** *(Opcional)*: Contraseña para inicio de sesión clásico/2FA. Si se omite, se genera una clave aleatoria segura.
- **`role`** *(Opcional, por defecto: `user`)*: Nombre del rol asignado (`user` o `admin`).
- **`phone_number`** *(Opcional)*: Número telefónico en formato internacional E.164.

- **Respuesta 200 OK:**
```json
{
  "message": "CSV user import completed successfully.",
  "total_processed": 3,
  "users_created": 3,
  "duplicates_skipped": 0,
  "errors": []
}
```

---

## 📊 5. Observabilidad y Monitoreo SIEM

### 5.1 `GET /metrics`
Exportador de métricas en formato estándar de **Prometheus**.

- **Respuesta 200 OK (`text/plain`):**
```prometheus
# HELP rba_evaluations_total Total count of Risk-Based OTP evaluations by risk level
# TYPE rba_evaluations_total counter
rba_evaluations_total{risk_level="low"} 56
rba_evaluations_total{risk_level="medium"} 31
rba_evaluations_total{risk_level="high"} 27

# HELP dag_revocations_total Total count of DAG token family tree revocations due to token reuse
# TYPE dag_revocations_total counter
dag_revocations_total 1
```

---

### 5.2 `GET /dashboard`
Interfaz gráfica interactiva Glassmorphic de monitoreo en tiempo real y consola SIEM.

- **Formato:** `text/html`
- **Ruta Directa:** [http://localhost:8000/dashboard](http://localhost:8000/dashboard)

---

## 📋 6. Matriz de Códigos de Estado HTTP

| Código HTTP | Definición | Descripción |
| :--- | :--- | :--- |
| **`200 OK`** | Petición Exitosa | Operación completada y datos devueltos correctamente. |
| **`400 Bad Request`** | Error en Parámetros | Fallo en la verificación del PoW o parámetros del payload inválidos. |
| **`401 Unauthorized`** | Error de Autenticación | Código OTP erróneo, expirado o detección de reuso de token en DAG. |
| **`403 Forbidden`** | Permiso Insuficiente | El usuario autenticado carece del rol o permiso RBAC requerido. |
| **`429 Too Many Requests`** | Límite Superado | Tasa de peticiones límite superada (>3 req/min) o bloqueo temporal por reintentos fallidos. |
| **`500 Internal Server Error`** | Error de Servidor | Excepción no controlada en el backend. |
