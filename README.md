# 🛡️ Arquitectura de Autenticación Zero-Trust con Autenticación Adaptativa Basada en Riesgo y Control Criptográfico de Sesiones
**Autor:** M.C. José Alonso Macías Montoya / Universidad Politécnica de Chiapas  
**Licencia:** [MIT (Custom Extended)](LICENSE)  

[![FastAPI](https://img.shields.io/badge/FastAPI-0.110+-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.12+-3776AB.svg?style=flat&logo=python)](https://www.python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat&logo=docker)](https://www.docker.com)
[![Prometheus](https://img.shields.io/badge/Prometheus-Metrics-E6522C.svg?style=flat&logo=prometheus)](http://localhost:8000/metrics)
[![Timezone](https://img.shields.io/badge/Timezone-America%2FMexico__City%20(GMT--6)-blue.svg)](#)

API REST de nivel empresarial y marco de investigación para **Autenticación Passwordless y 2FA Basada en Zero-Trust**, combinando protección criptográfica en el cliente, motor de riesgo contextual adaptativo y trazabilidad en tiempo real.

---

## 🌟 Arquitectura y Características Principales

1. **🛡️ Escudo Proof-of-Work (PoW):**
   - Mitigación de ataques de fuerza bruta y botnets mediante desafíos criptográficos SHA-256 en el cliente (`/auth/pow-challenge`) sin captchas invasivos.

2. **🧠 Motor de Riesgo Contextual Híbrido (RBA) de 8 Vectores:**
   - Evaluación dinámica de riesgo ($R \in [0, 1]$) combinando heurística y **Machine Learning (Isolation Forest)**:
     - Firmas de bots en User-Agent.
     - Anomalías de red/IP.
     - Dispositivos no reconocidos (`is_new_device`).
     - Alertas de velocidad geográfica imposible ($\Delta d / \Delta t > 900 \text{ km/h}$).
     - Historial de intentos fallidos.
     - Horario de acceso (01:00 - 05:00 UTC).
     - Encabezados de cliente (`Sec-CH-UA`).
     - **Detección de Anomalías con Machine Learning (Isolation Forest Model).**

3. **🔐 Autenticación Biométrica WebAuthn FIDO2 / Passkeys:**
   - Soporte nativo para acceso hardware por huella/rostro (TouchID, FaceID, YubiKey) en `/auth/webauthn/*`.

4. **⚡ Motor JSON Configurable de Ultra-Baja Latencia (`JSON_PARSER_ENGINE`):**
   - Soporte dinámico para **`msgspec`** (Nativo C/Rust) resultando **4.26x más rápido que Pydantic/json** ($4.13 \text{ µs/op}$ vs $17.63 \text{ µs/op}$).

5. **🌳 Rotación de Tokens JWT con Grafo DAG (Directed Acyclic Graph):**
   - Detección de reuso de Refresh Tokens con **revocación inmediata en cascada de la familia completa de sesiones en $<0.1 \text{ ms}$**.

6. **📈 Dashboard Interactivo y Telemetría Prometheus:**
   - Visualización en tiempo real en `/dashboard` con gráficos Chart.js, simulador interactivo de ataques DAG y logs SIEM.
   - Soporte para **Resend**, **Brevo**, **Mailtrap** y **Gmail**.
   - Plantilla HTML responsiva con personalización completa vía variables de entorno (`EMAIL_*`).

---

## 📊 Comparativa con el Estado del Arte (SOTA)

| Dimensión de Análisis | OTP Tradicional (SMS/Email) | Plataformas SaaS (Auth0 / Okta) | WebAuthn / FIDO2 | **Nuestra Arquitectura Zero-Trust** |
| :--- | :--- | :--- | :--- | :--- |
| **Defensa Perimetral DoS** | Limitación de tasa por IP (Vulnerable a proxies) | CAPTCHA / Cloudflare (Fricción de usuario) | N/A en capa de generación OTP | **Escudo PoW SHA-256 en Cliente (Cero fricción UX, invalida bots)** |
| **Entropía OTP** | Estática ($19.93\text{ bits}$, 6 dígitos) | Fija por tenant | N/A (Clave Asimétrica) | **Adaptativa Basada en Riesgo ($19.93$ a $59.54\text{ bits}$)** |
| **Detección de Riesgo** | Ninguna o estática por IP | Motor RBA propietario (Costo por evento) | Basado en dispositivo local | **Motor 7 Vectores Contextuales (0.0 a 1.0)** |
| **Revocación por Reuso** | Inexistente o por lista negra manual | Revocación periódica | N/A | **Revocación DAG Árbol Completo ($<0.1\text{ ms}$)** |
| **Dependencia Externa** | Proveedores SMS (Twilio/AWS) | Lock-in de proveedor SaaS | Soporte de hardware cliente | **Self-Hosted / Open-Source / Cero Dependencias** |

---

## 🛠️ Stack Tecnológico

- **Lenguaje & Framework:** Python 3.12+ con FastAPI.
- **Servidor ASGI:** Granian (Servidor nativo en Rust de alto rendimiento).
- **Base de Datos & ORM:** SQLite AsyncIO en modo WAL (Write-Ahead Logging) / PostgreSQL con SQLAlchemy 2.0 & Alembic.
- **Seguridad & Hash:** Argon2id (`argon2-cffi`), PyJWT (Access & Refresh Tokens).
- **Observabilidad:** Structlog con sanitización de PII (`RedactPIIProcessor`) y Prometheus client.
- **Contenedores:** Multi-stage Dockerfile ajustado en zona horaria `America/Mexico_City` (GMT-6).

---

## 🚀 Guía de Inicio Rápido con Docker

```bash
# 1. Clonar el repositorio
git clone https://github.com/alonsomaciasm/otp-auth-api
cd otp-auth-api

# 2. Configurar variables de entorno
cp .env.example .env

# 3. Construir e iniciar el contenedor Docker
docker build -t otp-auth-api:latest .
docker run -d --name otp_container --env-file .env -p 8000:8000 otp-auth-api:latest

# 4. Verificar salud del servicio
curl http://localhost:8000/api/v1/health
```

---

## 🌐 Endpoints Clave

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| `GET` | `/dashboard` | Dashboard Interactivo de Seguridad en Tiempo Real |
| `GET` | `/metrics` | Exportador de Métricas Prometheus |
| `GET` | `/docs` | Documentación Interactiva OpenAPI / Swagger UI |
| `GET` | `/api/v1/auth/pow-challenge` | Solicitar Desafío Proof-of-Work (PoW) |
| `POST` | `/api/v1/auth/request-otp` | Generar y enviar Código OTP con evaluación RBA |
| `POST` | `/api/v1/auth/verify-otp` | Verificar OTP y emitir Par de Tokens JWT |
| `POST` | `/api/v1/auth/refresh` | Rotar Refresh Token con detección de reuso DAG |
