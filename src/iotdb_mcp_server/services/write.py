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


def _assert_write_permission(
    config: Config, action: str, confirm_delete: bool = False
) -> None:
    if not _env_bool("IOTDB_ENABLE_WRITE_DML", False):
        raise PermissionError(
            "Write DML tools are disabled by server policy. "
            "Set IOTDB_ENABLE_WRITE_DML=true to enable."
        )

    allowed_users = _csv_set(os.getenv("IOTDB_WRITE_ALLOWED_USERS", "root"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_WRITE_ALLOWED_USERS."
        )

    if (
        action == "DELETE"
        and _env_bool("IOTDB_REQUIRE_DELETE_CONFIRM", True)
        and not confirm_delete
    ):
        raise PermissionError("DELETE operation requires confirm_delete=True by server policy.")


def _normalize_sql(sql: str) -> str:
    cleaned = sql.strip()
    if not cleaned:
        raise ValueError("Write SQL cannot be empty.")
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if ";" in cleaned:
        raise ValueError("Only a single SQL statement is allowed.")
    return cleaned


def register_write_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register write-related DML tools for tree/table sql dialect."""
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
        async def write_query(write_sql: str, confirm_delete: bool = False) -> list[TextContent]:
            """Execute tree-model write SQL (INSERT/DELETE).

            Supported prefixes:
            - INSERT INTO
            - DELETE FROM
            """
            session = None
            try:
                sql = _normalize_sql(write_sql)
                upper = sql.upper()

                if upper.startswith("INSERT INTO"):
                    _assert_write_permission(config, action="INSERT")
                elif upper.startswith("DELETE FROM"):
                    _assert_write_permission(
                        config, action="DELETE", confirm_delete=confirm_delete
                    )
                else:
                    raise ValueError(
                        "tree write_query only supports SQL starting with: INSERT INTO, DELETE FROM"
                    )

                session = session_pool.get_session()
                session.execute_non_query_statement(sql)
                session.close()
                return sql_success_response("write_query", sql)
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to execute tree write_query: {str(e)}")
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
        async def write_query(write_sql: str, confirm_delete: bool = False) -> list[TextContent]:
            """Execute table-model write SQL (INSERT/UPDATE/DELETE).

            Supported prefixes:
            - INSERT INTO
            - UPDATE
            - DELETE FROM
            - DELETE DEVICES
            """
            table_session = None
            try:
                sql = _normalize_sql(write_sql)
                upper = sql.upper()

                if upper.startswith("INSERT INTO"):
                    _assert_write_permission(config, action="INSERT")
                elif upper.startswith("UPDATE"):
                    _assert_write_permission(config, action="UPDATE")
                elif upper.startswith("DELETE FROM") or upper.startswith("DELETE DEVICES"):
                    _assert_write_permission(
                        config, action="DELETE", confirm_delete=confirm_delete
                    )
                else:
                    raise ValueError(
                        "table write_query only supports SQL starting with: "
                        "INSERT INTO, UPDATE, DELETE FROM, DELETE DEVICES"
                    )

                table_session = session_pool.get_session()
                table_session.execute_non_query_statement(sql)
                table_session.close()
                return sql_success_response("write_query", sql)
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to execute table write_query: {str(e)}")
                raise

    else:
        raise ValueError(
            f"Unsupported sql_dialect '{config.sql_dialect}'. Expected 'tree' or 'table'."
        )
