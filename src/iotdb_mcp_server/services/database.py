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
import re

from iotdb.Session import Session
from iotdb.SessionPool import PoolConfig, SessionPool
from iotdb.table_session import TableSession
from iotdb.table_session_pool import TableSessionPool, TableSessionPoolConfig
from iotdb.utils.SessionDataSet import SessionDataSet
from mcp.types import TextContent

from iotdb_mcp_server.config import Config

_TABLE_DB_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_TREE_DB_PATTERN = re.compile(r"^root(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _assert_database_ddl_permission(
    config: Config, action: str, confirm: bool = False
) -> None:
    # Gate 1: service-level switch for DDL tools
    if not _env_bool("IOTDB_ENABLE_DATABASE_DDL", False):
        raise PermissionError(
            "Database DDL tool is disabled by server policy. "
            "Set IOTDB_ENABLE_DATABASE_DDL=true to enable."
        )

    # Gate 2: service-level user allowlist
    allowed_users = _csv_set(os.getenv("IOTDB_DATABASE_DDL_ALLOWED_USERS", "root"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_DATABASE_DDL_ALLOWED_USERS."
        )

    # Gate 3: explicit confirmation for destructive DROP
    if action == "DROP" and _env_bool("IOTDB_REQUIRE_DROP_CONFIRM", True) and not confirm:
        raise PermissionError(
            "DROP DATABASE requires confirm=True by server policy."
        )


def _validate_database_name(sql_dialect: str, database: str) -> str:
    raw = database.strip()
    if not raw:
        raise ValueError("Database name/path cannot be empty.")

    if sql_dialect == "tree":
        if not _TREE_DB_PATTERN.fullmatch(raw):
            raise ValueError(
                "Invalid tree database path. Expected pattern like root.sg or root.sg1.dev."
            )
    elif sql_dialect == "table":
        if not _TABLE_DB_PATTERN.fullmatch(raw):
            raise ValueError(
                "Invalid table database name. Use letters, numbers, and underscore only."
            )
    else:
        raise ValueError(
            f"Unsupported sql_dialect '{sql_dialect}'. Expected 'tree' or 'table'."
        )
    return raw


def _format_result(
    res: SessionDataSet, session_or_table_session: Session | TableSession
) -> list[TextContent]:
    columns = res.get_column_names()
    rows: list[str] = []
    while res.has_next():
        row = res.next().get_fields()
        rows.append(",".join(map(str, row)))
    session_or_table_session.close()
    return [TextContent(type="text", text="\n".join([",".join(columns)] + rows))]


def register_database_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register database management tools for tree/table sql dialect."""
    max_pool_size = 100

    if config.sql_dialect == "tree":
        pool_config = PoolConfig(
            node_urls=[str(config.host) + ":" + str(config.port)],
            user_name=config.user,
            password=config.password,
            fetch_size=1024,
            time_zone="UTC+8",
            max_retry=3,
        )
        session_pool = SessionPool(pool_config, max_pool_size, 5000)

        @mcp.tool()
        async def list_databases(details: bool = False) -> list[TextContent]:
            """List databases in tree model."""
            session = None
            try:
                session = session_pool.get_session()
                sql = "SHOW DATABASES DETAILS" if details else "SHOW DATABASES"
                res = session.execute_query_statement(sql)
                return _format_result(res, session)
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to list databases: {str(e)}")
                raise

        @mcp.tool()
        async def create_database(database: str) -> list[TextContent]:
            """Create a tree-model database (path like root.sg)."""
            session = None
            try:
                _assert_database_ddl_permission(config, action="CREATE")
                database_path = _validate_database_name(config.sql_dialect, database)
                sql = f"CREATE DATABASE {database_path}"
                session = session_pool.get_session()
                session.execute_non_query_statement(sql)
                session.close()
                return [TextContent(type="text", text=f"Success: {sql}")]
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to create database: {str(e)}")
                raise

        @mcp.tool()
        async def drop_database(database: str, confirm: bool = False) -> list[TextContent]:
            """Drop a tree-model database (destructive)."""
            session = None
            try:
                _assert_database_ddl_permission(
                    config, action="DROP", confirm=confirm
                )
                database_path = _validate_database_name(config.sql_dialect, database)
                sql = f"DROP DATABASE {database_path}"
                session = session_pool.get_session()
                session.execute_non_query_statement(sql)
                session.close()
                return [TextContent(type="text", text=f"Success: {sql}")]
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to drop database: {str(e)}")
                raise

    elif config.sql_dialect == "table":
        session_pool_config = TableSessionPoolConfig(
            node_urls=[str(config.host) + ":" + str(config.port)],
            username=config.user,
            password=config.password,
            max_pool_size=max_pool_size,
            database=None if len(config.database) == 0 else config.database,
        )
        session_pool = TableSessionPool(session_pool_config)

        @mcp.tool()
        async def list_databases(details: bool = False) -> list[TextContent]:
            """List databases in table model."""
            table_session = None
            try:
                table_session = session_pool.get_session()
                sql = "SHOW DATABASES DETAILS" if details else "SHOW DATABASES"
                res = table_session.execute_query_statement(sql)
                return _format_result(res, table_session)
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to list databases: {str(e)}")
                raise

        @mcp.tool()
        async def create_database(
            database: str, if_not_exists: bool = True
        ) -> list[TextContent]:
            """Create a table-model database."""
            table_session = None
            try:
                _assert_database_ddl_permission(config, action="CREATE")
                database_name = _validate_database_name(config.sql_dialect, database)
                sql = (
                    f"CREATE DATABASE IF NOT EXISTS {database_name}"
                    if if_not_exists
                    else f"CREATE DATABASE {database_name}"
                )
                table_session = session_pool.get_session()
                table_session.execute_non_query_statement(sql)
                table_session.close()
                return [TextContent(type="text", text=f"Success: {sql}")]
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to create database: {str(e)}")
                raise

        @mcp.tool()
        async def drop_database(
            database: str, if_exists: bool = True, confirm: bool = False
        ) -> list[TextContent]:
            """Drop a table-model database (destructive)."""
            table_session = None
            try:
                _assert_database_ddl_permission(
                    config, action="DROP", confirm=confirm
                )
                database_name = _validate_database_name(config.sql_dialect, database)
                sql = (
                    f"DROP DATABASE IF EXISTS {database_name}"
                    if if_exists
                    else f"DROP DATABASE {database_name}"
                )
                table_session = session_pool.get_session()
                table_session.execute_non_query_statement(sql)
                table_session.close()
                return [TextContent(type="text", text=f"Success: {sql}")]
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to drop database: {str(e)}")
                raise

        @mcp.tool()
        async def use_database(database: str) -> list[TextContent]:
            """Switch current database in table model session."""
            table_session = None
            try:
                database_name = _validate_database_name(config.sql_dialect, database)
                sql = f"USE {database_name}"
                table_session = session_pool.get_session()
                table_session.execute_non_query_statement(sql)
                table_session.close()
                return [TextContent(type="text", text=f"Success: {sql}")]
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to use database: {str(e)}")
                raise
    else:
        raise ValueError(
            f"Unsupported sql_dialect '{config.sql_dialect}'. Expected 'tree' or 'table'."
        )
