#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

import logging
import os

from iotdb.SessionPool import PoolConfig, SessionPool
from mcp.types import TextContent

from iotdb_mcp_server.config import Config


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _assert_timeseries_ddl_permission(
    config: Config, action: str, confirm: bool = False
) -> None:
    if not _env_bool("IOTDB_ENABLE_TIMESERIES_DDL", False):
        raise PermissionError(
            "Timeseries DDL tools are disabled by server policy. "
            "Set IOTDB_ENABLE_TIMESERIES_DDL=true to enable."
        )

    allowed_users = _csv_set(os.getenv("IOTDB_TIMESERIES_DDL_ALLOWED_USERS", "root"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_TIMESERIES_DDL_ALLOWED_USERS."
        )

    if (
        action == "DROP"
        and _env_bool("IOTDB_REQUIRE_TIMESERIES_DROP_CONFIRM", True)
        and not confirm
    ):
        raise PermissionError(
            "DROP/DELETE TIMESERIES requires confirm=True by server policy."
        )


def _normalize_sql(sql: str) -> str:
    cleaned = sql.strip()
    if not cleaned:
        raise ValueError("DDL SQL cannot be empty.")
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if ";" in cleaned:
        raise ValueError("Only a single SQL statement is allowed.")
    return cleaned


def _ensure_prefix(sql: str, allowed_prefixes: tuple[str, ...], action_name: str) -> None:
    upper = sql.upper()
    if not upper.startswith(allowed_prefixes):
        raise ValueError(
            f"{action_name} only supports SQL starting with: {', '.join(allowed_prefixes)}"
        )


def register_timeseries_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register tree-model timeseries-level DDL tools."""
    if config.sql_dialect != "tree":
        logger.info(
            "Skip timeseries DDL tools because sql_dialect=%s (requires tree).",
            config.sql_dialect,
        )
        return

    pool_config = PoolConfig(
        node_urls=[str(config.host) + ":" + str(config.port)],
        user_name=config.user,
        password=config.password,
        fetch_size=1024,
        time_zone="UTC+8",
        max_retry=3,
    )
    session_pool = SessionPool(pool_config, 100, 5000)

    @mcp.tool()
    async def create_timeseries_ddl(ddl_sql: str) -> list[TextContent]:
        """Execute tree-model CREATE TIMESERIES DDL.

        Supported prefixes:
        - CREATE TIMESERIES
        - CREATE ALIGNED TIMESERIES
        """
        session = None
        try:
            _assert_timeseries_ddl_permission(config, action="CREATE")
            sql = _normalize_sql(ddl_sql)
            _ensure_prefix(
                sql,
                ("CREATE TIMESERIES", "CREATE ALIGNED TIMESERIES"),
                "create_timeseries_ddl",
            )
            session = session_pool.get_session()
            session.execute_non_query_statement(sql)
            session.close()
            return [TextContent(type="text", text=f"Success: {sql}")]
        except Exception as e:
            if session:
                session.close()
            logger.error(f"Failed to execute create_timeseries_ddl: {str(e)}")
            raise

    @mcp.tool()
    async def alter_timeseries_ddl(ddl_sql: str) -> list[TextContent]:
        """Execute tree-model ALTER TIMESERIES DDL."""
        session = None
        try:
            _assert_timeseries_ddl_permission(config, action="ALTER")
            sql = _normalize_sql(ddl_sql)
            _ensure_prefix(sql, ("ALTER TIMESERIES",), "alter_timeseries_ddl")
            session = session_pool.get_session()
            session.execute_non_query_statement(sql)
            session.close()
            return [TextContent(type="text", text=f"Success: {sql}")]
        except Exception as e:
            if session:
                session.close()
            logger.error(f"Failed to execute alter_timeseries_ddl: {str(e)}")
            raise

    @mcp.tool()
    async def drop_timeseries_ddl(
        ddl_sql: str, confirm: bool = False
    ) -> list[TextContent]:
        """Execute tree-model DROP/DELETE TIMESERIES DDL (destructive)."""
        session = None
        try:
            _assert_timeseries_ddl_permission(
                config, action="DROP", confirm=confirm
            )
            sql = _normalize_sql(ddl_sql)
            _ensure_prefix(
                sql,
                ("DROP TIMESERIES", "DELETE TIMESERIES"),
                "drop_timeseries_ddl",
            )
            session = session_pool.get_session()
            session.execute_non_query_statement(sql)
            session.close()
            return [TextContent(type="text", text=f"Success: {sql}")]
        except Exception as e:
            if session:
                session.close()
            logger.error(f"Failed to execute drop_timeseries_ddl: {str(e)}")
            raise
