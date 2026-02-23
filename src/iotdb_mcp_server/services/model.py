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

from iotdb.Session import Session
from iotdb.SessionPool import PoolConfig, SessionPool
from iotdb.table_session import TableSession
from iotdb.table_session_pool import TableSessionPool, TableSessionPoolConfig
from iotdb.utils.SessionDataSet import SessionDataSet
from mcp.types import TextContent

from iotdb_mcp_server.config import Config


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _assert_model_permission(
    config: Config, action: str, confirm_destructive: bool = False
) -> None:
    if not _env_bool("IOTDB_ENABLE_MODEL_MANAGEMENT", False):
        raise PermissionError(
            "AINode model tools are disabled by server policy. "
            "Set IOTDB_ENABLE_MODEL_MANAGEMENT=true to enable."
        )

    allowed_users = _csv_set(os.getenv("IOTDB_MODEL_ALLOWED_USERS", "root"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_MODEL_ALLOWED_USERS."
        )

    if (
        action == "DESTRUCTIVE"
        and _env_bool("IOTDB_REQUIRE_MODEL_DESTRUCTIVE_CONFIRM", True)
        and not confirm_destructive
    ):
        raise PermissionError(
            "Destructive model command requires confirm_destructive=True by server policy."
        )


def _normalize_sql(sql: str) -> str:
    cleaned = sql.strip()
    if not cleaned:
        raise ValueError("Model SQL cannot be empty.")
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if ";" in cleaned:
        raise ValueError("Only a single SQL statement is allowed.")
    return cleaned


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


def register_model_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register AINode model-management SQL tools."""
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
        async def model_query(model_sql: str) -> list[TextContent]:
            """Execute AINode model-query SQL.

            Supported prefixes:
            - SHOW MODELS
            - SHOW LOADED MODELS
            - SHOW AI_DEVICES
            - SHOW AINODES
            """
            session = None
            try:
                _assert_model_permission(config, action="QUERY")
                sql = _normalize_sql(model_sql)
                upper = sql.upper()
                if not upper.startswith(
                    (
                        "SHOW MODELS",
                        "SHOW LOADED MODELS",
                        "SHOW AI_DEVICES",
                        "SHOW AINODES",
                    )
                ):
                    raise ValueError(
                        "model_query only supports SQL starting with: "
                        "SHOW MODELS, SHOW LOADED MODELS, SHOW AI_DEVICES, SHOW AINODES"
                    )
                session = session_pool.get_session()
                res = session.execute_query_statement(sql)
                return _format_result(res, session)
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to execute model_query: {str(e)}")
                raise

        @mcp.tool()
        async def model_command(
            model_sql: str, confirm_destructive: bool = False
        ) -> list[TextContent]:
            """Execute AINode model-management command SQL.

            Supported prefixes:
            - CREATE MODEL
            - DROP MODEL
            - LOAD MODEL
            - UNLOAD MODEL
            - REMOVE AINODE
            """
            session = None
            try:
                sql = _normalize_sql(model_sql)
                upper = sql.upper()

                if upper.startswith(("DROP MODEL", "UNLOAD MODEL", "REMOVE AINODE")):
                    _assert_model_permission(
                        config,
                        action="DESTRUCTIVE",
                        confirm_destructive=confirm_destructive,
                    )
                elif upper.startswith(("CREATE MODEL", "LOAD MODEL")):
                    _assert_model_permission(config, action="MANAGE")
                else:
                    raise ValueError(
                        "model_command only supports SQL starting with: "
                        "CREATE MODEL, DROP MODEL, LOAD MODEL, UNLOAD MODEL, REMOVE AINODE"
                    )

                session = session_pool.get_session()
                session.execute_non_query_statement(sql)
                session.close()
                return [TextContent(type="text", text=f"Success: {sql}")]
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to execute model_command: {str(e)}")
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
        async def model_query(model_sql: str) -> list[TextContent]:
            """Execute AINode model-query SQL.

            Supported prefixes:
            - SHOW MODELS
            - SHOW LOADED MODELS
            - SHOW AI_DEVICES
            - SHOW AINODES
            """
            table_session = None
            try:
                _assert_model_permission(config, action="QUERY")
                sql = _normalize_sql(model_sql)
                upper = sql.upper()
                if not upper.startswith(
                    (
                        "SHOW MODELS",
                        "SHOW LOADED MODELS",
                        "SHOW AI_DEVICES",
                        "SHOW AINODES",
                    )
                ):
                    raise ValueError(
                        "model_query only supports SQL starting with: "
                        "SHOW MODELS, SHOW LOADED MODELS, SHOW AI_DEVICES, SHOW AINODES"
                    )
                table_session = session_pool.get_session()
                res = table_session.execute_query_statement(sql)
                return _format_result(res, table_session)
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to execute model_query: {str(e)}")
                raise

        @mcp.tool()
        async def model_command(
            model_sql: str, confirm_destructive: bool = False
        ) -> list[TextContent]:
            """Execute AINode model-management command SQL.

            Supported prefixes:
            - CREATE MODEL
            - DROP MODEL
            - LOAD MODEL
            - UNLOAD MODEL
            - REMOVE AINODE
            """
            table_session = None
            try:
                sql = _normalize_sql(model_sql)
                upper = sql.upper()

                if upper.startswith(("DROP MODEL", "UNLOAD MODEL", "REMOVE AINODE")):
                    _assert_model_permission(
                        config,
                        action="DESTRUCTIVE",
                        confirm_destructive=confirm_destructive,
                    )
                elif upper.startswith(("CREATE MODEL", "LOAD MODEL")):
                    _assert_model_permission(config, action="MANAGE")
                else:
                    raise ValueError(
                        "model_command only supports SQL starting with: "
                        "CREATE MODEL, DROP MODEL, LOAD MODEL, UNLOAD MODEL, REMOVE AINODE"
                    )

                table_session = session_pool.get_session()
                table_session.execute_non_query_statement(sql)
                table_session.close()
                return [TextContent(type="text", text=f"Success: {sql}")]
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to execute model_command: {str(e)}")
                raise
    else:
        raise ValueError(
            f"Unsupported sql_dialect '{config.sql_dialect}'. Expected 'tree' or 'table'."
        )
