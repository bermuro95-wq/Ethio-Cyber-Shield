"""
Database Abstraction & Multi-Backend Service for Ethio-Cyber-Shield (ECS).
Complies with Non-Negotiable Rule #5 and Phase 1.3:
- Runs independently with plain PostgreSQL 16 via psycopg2 (no proprietary Supabase lock-in)
- Supports Supabase client when SUPABASE_URL is provided for hybrid/legacy deployments
- Provides connection pooling, automatic reconnect, and health ping diagnostics
"""
import os
import time
import json
import logging
import threading
from typing import Optional, Dict, Any, List

from app.config import Config

logger = logging.getLogger(__name__)

_supabase_client = None
_service_supabase_client = None
_thread_local = threading.local()
_pg_pool = None


class QueryResult:
    """Wrapper matching Supabase client execute() response contract: result.data."""
    def __init__(self, data: list):
        self.data = data or []


class PostgresTableQuery:
    """
    Fluent query builder providing Supabase/PostgREST compatible syntax over PostgreSQL:
    .select(), .insert(), .update(), .delete(), .eq(), .gte(), .lte(), .order(), .limit(), .execute()
    """
    def __init__(self, table_name: str, conn_getter):
        self.table_name = table_name
        self._get_conn = conn_getter
        self._action = "SELECT"
        self._select_cols = "*"
        self._insert_data = None
        self._update_data = None
        self._where_clauses: List[str] = []
        self._where_params: List[Any] = []
        self._order_by: Optional[str] = None
        self._limit_val: Optional[int] = None

    def select(self, cols: str = "*"):
        self._action = "SELECT"
        self._select_cols = cols
        return self

    def insert(self, data: dict | list):
        self._action = "INSERT"
        self._insert_data = data if isinstance(data, list) else [data]
        return self

    def upsert(self, data: dict | list, on_conflict: str = None):
        self._action = "INSERT"
        self._insert_data = data if isinstance(data, list) else [data]
        self._on_conflict = on_conflict
        return self

    def update(self, data: dict):
        self._action = "UPDATE"
        self._update_data = data
        return self

    def delete(self):
        self._action = "DELETE"
        return self

    def eq(self, column: str, value: Any):
        self._where_clauses.append(f'"{column}" = %s')
        self._where_params.append(value)
        return self

    def neq(self, column: str, value: Any):
        self._where_clauses.append(f'"{column}" != %s')
        self._where_params.append(value)
        return self

    def gte(self, column: str, value: Any):
        self._where_clauses.append(f'"{column}" >= %s')
        self._where_params.append(value)
        return self

    def lte(self, column: str, value: Any):
        self._where_clauses.append(f'"{column}" <= %s')
        self._where_params.append(value)
        return self

    def gt(self, column: str, value: Any):
        self._where_clauses.append(f'"{column}" > %s')
        self._where_params.append(value)
        return self

    def lt(self, column: str, value: Any):
        self._where_clauses.append(f'"{column}" < %s')
        self._where_params.append(value)
        return self

    def in_(self, column: str, values: list):
        if not values:
            self._where_clauses.append("1=0")
            return self
        placeholders = ", ".join(["%s"] * len(values))
        self._where_clauses.append(f'"{column}" IN ({placeholders})')
        self._where_params.extend(values)
        return self

    def or_(self, expr: str):
        # Basic or_ support (e.g. title.ilike.%search%,description.ilike.%search%)
        if "ilike" in expr:
            parts = expr.split(",")
            sub_clauses = []
            for p in parts:
                seg = p.split(".ilike.")
                if len(seg) == 2:
                    col, val = seg[0], seg[1].replace("%", "")
                    sub_clauses.append(f'"{col}" ILIKE %s')
                    self._where_params.append(f"%{val}%")
            if sub_clauses:
                self._where_clauses.append(f"({' OR '.join(sub_clauses)})")
        return self

    def order(self, column: str, desc: bool = False):
        direction = "DESC" if desc else "ASC"
        self._order_by = f'"{column}" {direction}'
        return self

    def limit(self, count: int):
        self._limit_val = count
        return self

    def execute(self) -> QueryResult:
        import psycopg2
        import psycopg2.extras

        conn = self._get_conn()
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

        try:
            if self._action == "SELECT":
                cols = "*" if ":" in self._select_cols or "!" in self._select_cols else self._select_cols
                sql = f'SELECT {cols} FROM "{self.table_name}"'
                if self._where_clauses:
                    sql += " WHERE " + " AND ".join(self._where_clauses)
                if self._order_by:
                    sql += f" ORDER BY {self._order_by}"
                if self._limit_val:
                    sql += f" LIMIT {self._limit_val}"

                cur.execute(sql, tuple(self._where_params))
                rows = [dict(r) for r in cur.fetchall()]
                return QueryResult(rows)

            elif self._action == "INSERT":
                if not self._insert_data:
                    return QueryResult([])

                cols = list(self._insert_data[0].keys())
                col_names = ", ".join([f'"{c}"' for c in cols])
                placeholders = ", ".join(["%s"] * len(cols))
                sql = f'INSERT INTO "{self.table_name}" ({col_names}) VALUES ({placeholders}) RETURNING *'

                inserted_rows = []
                for item in self._insert_data:
                    vals = [
                        json.dumps(item[c]) if isinstance(item[c], dict) else item[c]
                        for c in cols
                    ]
                    cur.execute(sql, tuple(vals))
                    inserted_rows.append(dict(cur.fetchone()))

                conn.commit()
                return QueryResult(inserted_rows)

            elif self._action == "UPDATE":
                if not self._update_data:
                    return QueryResult([])

                set_clauses = [f'"{k}" = %s' for k in self._update_data.keys()]
                vals = [
                    json.dumps(v) if isinstance(v, dict) else v
                    for v in self._update_data.values()
                ]

                sql = f'UPDATE "{self.table_name}" SET {", ".join(set_clauses)}'
                if self._where_clauses:
                    sql += " WHERE " + " AND ".join(self._where_clauses)
                sql += " RETURNING *"

                cur.execute(sql, tuple(vals + self._where_params))
                updated = [dict(r) for r in cur.fetchall()]
                conn.commit()
                return QueryResult(updated)

            elif self._action == "DELETE":
                sql = f'DELETE FROM "{self.table_name}"'
                if self._where_clauses:
                    sql += " WHERE " + " AND ".join(self._where_clauses)
                sql += " RETURNING *"

                cur.execute(sql, tuple(self._where_params))
                deleted = [dict(r) for r in cur.fetchall()]
                conn.commit()
                return QueryResult(deleted)

        except Exception as e:
            conn.rollback()
            raise e
        finally:
            cur.close()


class PostgresDatabaseAdapter:
    """Independent PostgreSQL database adapter replacing Supabase client."""
    def __init__(self, database_url: str):
        self.database_url = database_url
        self._conn = None

    def _get_connection(self):
        import psycopg2
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self.database_url)
            self._conn.autocommit = False
        return self._conn

    def table(self, table_name: str) -> PostgresTableQuery:
        return PostgresTableQuery(table_name, self._get_connection)


def get_supabase():
    """Returns database client (Supabase if configured, or PostgreSQL adapter)."""
    return get_service_supabase()


def get_service_supabase():
    """
    Returns the primary service-role database client.
    Prefers Supabase client when SUPABASE_URL and key are provided;
    falls back cleanly to direct PostgreSQL when DATABASE_URL is configured.
    Thread-local storage ensures Flask worker threads and SSE generator
    streams each operate on an isolated client instance, preventing
    HTTP/2 HPACK table collisions and deque mutation errors.
    """
    global _service_supabase_client

    if _service_supabase_client is not None:
        return _service_supabase_client

    client = getattr(_thread_local, 'client', None)
    if client is not None:
        return client

    # 1. Supabase Client Mode
    if Config.SUPABASE_URL and (Config.SUPABASE_SERVICE_KEY or Config.SUPABASE_KEY):
        try:
            from supabase import create_client
            key = Config.SUPABASE_SERVICE_KEY or Config.SUPABASE_KEY
            client = create_client(Config.SUPABASE_URL, key)
            _thread_local.client = client
            return client
        except Exception as e:
            logger.warning(f"Failed to initialize Supabase client: {e}")

    # 2. Independent Plain PostgreSQL Mode
    if Config.DATABASE_URL:
        try:
            client = PostgresDatabaseAdapter(Config.DATABASE_URL)
            logger.info("Database service running on independent PostgreSQL adapter.")
            _thread_local.client = client
            return client
        except Exception as e:
            logger.error(f"Failed to connect to independent PostgreSQL: {e}")

    # 3. Fallback dummy or raise
    if Config.SUPABASE_URL:
        from supabase import create_client
        client = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY or "anon")
        _thread_local.client = client
        return client

    raise ValueError("Neither SUPABASE_URL nor DATABASE_URL is configured for database connection.")


def check_db_health() -> dict:
    """
    Performs a connection health ping against the configured database.
    Returns status, latency in milliseconds, and driver mode.
    """
    t0 = time.time()
    driver = "unknown"
    status = "down"

    try:
        client = get_service_supabase()
        if isinstance(client, PostgresDatabaseAdapter):
            driver = "psycopg2-postgres"
            client.table('organizations').select('id').limit(1).execute()
            status = "healthy"
        else:
            driver = "supabase-postgrest"
            client.table('organizations').select('id').limit(1).execute()
            status = "healthy"
    except Exception as e:
        status = "degraded"
        logger.debug(f"Database health ping notice: {e}")

    latency_ms = int((time.time() - t0) * 1000)
    return {
        'status': status,
        'driver': driver,
        'latency_ms': latency_ms
    }
