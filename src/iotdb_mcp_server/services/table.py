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

from iotdb.table_session_pool import TableSessionPool, TableSessionPoolConfig
from mcp.types import TextContent

from iotdb_mcp_server.config import Config
from iotdb_mcp_server.services.json_response import sql_success_response


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _assert_table_ddl_permission(
    config: Config, action: str, confirm: bool = False
) -> None:
    if not _env_bool("IOTDB_ENABLE_TABLE_DDL", False):
        raise PermissionError(
            "Table DDL tools are disabled by server policy. "
            "Set IOTDB_ENABLE_TABLE_DDL=true to enable."
        )

    allowed_users = _csv_set(os.getenv("IOTDB_TABLE_DDL_ALLOWED_USERS", "root"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_TABLE_DDL_ALLOWED_USERS."
        )

    if (
        action == "DROP"
        and _env_bool("IOTDB_REQUIRE_TABLE_DROP_CONFIRM", True)
        and not confirm
    ):
        raise PermissionError("DROP TABLE requires confirm=True by server policy.")


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


def register_table_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register table-model table-level DDL tools."""
    if config.sql_dialect != "table":
        logger.info(
            "Skip table DDL tools because sql_dialect=%s (requires table).",
            config.sql_dialect,
        )
        return

    session_pool_config = TableSessionPoolConfig(
        node_urls=[str(config.host) + ":" + str(config.port)],
        username=config.user,
        password=config.password,
        max_pool_size=100,
        database=None if len(config.database) == 0 else config.database,
    )
    session_pool = TableSessionPool(session_pool_config)

    @mcp.tool()
    async def create_table_ddl(ddl_sql: str) -> list[TextContent]:
        """Execute table-model CREATE TABLE DDL."""
        table_session = None
        try:
            _assert_table_ddl_permission(config, action="CREATE")
            sql = _normalize_sql(ddl_sql)
            _ensure_prefix(sql, ("CREATE TABLE",), "create_table_ddl")
            table_session = session_pool.get_session()
            table_session.execute_non_query_statement(sql)
            table_session.close()
            return sql_success_response("create_table_ddl", sql)
        except Exception as e:
            if table_session:
                table_session.close()
            logger.error(f"Failed to execute create_table_ddl: {str(e)}")
            raise

    @mcp.tool()
    async def alter_table_ddl(ddl_sql: str) -> list[TextContent]:
        """Execute table-model ALTER TABLE DDL."""
        table_session = None
        try:
            _assert_table_ddl_permission(config, action="ALTER")
            sql = _normalize_sql(ddl_sql)
            _ensure_prefix(sql, ("ALTER TABLE",), "alter_table_ddl")
            table_session = session_pool.get_session()
            table_session.execute_non_query_statement(sql)
            table_session.close()
            return sql_success_response("alter_table_ddl", sql)
        except Exception as e:
            if table_session:
                table_session.close()
            logger.error(f"Failed to execute alter_table_ddl: {str(e)}")
            raise

    @mcp.tool()
    async def drop_table_ddl(ddl_sql: str, confirm: bool = False) -> list[TextContent]:
        """Execute table-model DROP TABLE DDL (destructive)."""
        table_session = None
        try:
            _assert_table_ddl_permission(config, action="DROP", confirm=confirm)
            sql = _normalize_sql(ddl_sql)
            _ensure_prefix(sql, ("DROP TABLE",), "drop_table_ddl")
            table_session = session_pool.get_session()
            table_session.execute_non_query_statement(sql)
            table_session.close()
            return sql_success_response("drop_table_ddl", sql)
        except Exception as e:
            if table_session:
                table_session.close()
            logger.error(f"Failed to execute drop_table_ddl: {str(e)}")
            raise
