# 🗄️ Guía de Migración Transparente a PostgreSQL en Alta Disponibilidad

Esta arquitectura está diseñada mediante la abstracción ORM asíncrona de **SQLAlchemy 2.0 AsyncEngine**, lo que permite conmutar entre **SQLite AsyncIO (WAL)** en desarrollo/producción liviana y **PostgreSQL Cluster (AsyncPG)** en entornos de ultra-alta concurrencia de forma completamente transparente.

---

## 🛠️ 1. Cambio de Motor en Variables de Entorno

Para conmutar la base de datos a PostgreSQL, solo se requiere cambiar la variable `DATABASE_URL` en el archivo `.env` o en el entorno de ejecución de Docker / Kubernetes:

### Desarrollo / Producción Estándar (SQLite WAL):
```ini
DATABASE_URL=sqlite+aiosqlite:////app/data/sql_app.db
```

### Producción Multinodo / Alta Disponibilidad (PostgreSQL AsyncPG):
```ini
DATABASE_URL=postgresql+asyncpg://otp_user:SecurePassword123@postgres_host:5432/otp_auth_db
```

---

## 📦 2. Instalación del Driver AsyncPG (Si aplica)

El contenedor o entorno virtual requiere el controlador asíncrono `asyncpg`:

```bash
pip install asyncpg
```

---

## 🔄 3. Migraciones de Esquema con Alembic

Para aplicar la estructura de tablas y relaciones DAG en PostgreSQL:

```bash
# Ejecutar migraciones asíncronas
alembic upgrade head
```

---

## 📊 4. Beneficios de la Arquitectura de Desacoplamiento

- **Mismo Código de Dominio:** Ninguna consulta SQL o modelo (`User`, `Role`, `RefreshTokenSession`) requiere modificaciones.
- **Pooling Automático:** El motor `app/db/session.py` detecta PostgreSQL y habilita automáticamente el pool de conexiones de alta concurrencia (`pool_size=20`, `max_overflow=10`, `pool_pre_ping=True`).
- **Portabilidad Cero-Fricción:** Permite desplegar réplicas de lectura en Kubernetes con PostgreSQL RDS / Cloud SQL manteniendo sub-millisecond query performance.
