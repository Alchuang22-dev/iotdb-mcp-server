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


def _assert_ttl_permission(
    config: Config, action: str, confirm_unset: bool = False
) -> None:
    if not _env_bool("IOTDB_ENABLE_TTL_SQL", False):
        raise PermissionError(
            "TTL tools are disabled by server policy. "
            "Set IOTDB_ENABLE_TTL_SQL=true to enable."
        )

    allowed_users = _csv_set(os.getenv("IOTDB_TTL_ALLOWED_USERS", "root"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_TTL_ALLOWED_USERS."
        )

    if (
        action == "UNSET"
        and _env_bool("IOTDB_REQUIRE_TTL_UNSET_CONFIRM", True)
        and not confirm_unset
    ):
        raise PermissionError(
            "UNSET TTL requires confirm_unset=True by server policy."
        )


def _normalize_sql(sql: str) -> str:
    cleaned = sql.strip()
    if not cleaned:
        raise ValueError("TTL SQL cannot be empty.")
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if ";" in cleaned:
        raise ValueError("Only a single SQL statement is allowed.")
    return cleaned


def _format_result(res: SessionDataSet, session: Session) -> list[TextContent]:
    columns = res.get_column_names()
    rows: list[str] = []
    while res.has_next():
        row = res.next().get_fields()
        rows.append(",".join(map(str, row)))
    session.close()
    return [TextContent(type="text", text="\n".join([",".join(columns)] + rows))]


def register_ttl_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register TTL SQL tools.

    Note: TTL grammar is tree-model SQL.
    """
    if config.sql_dialect != "tree":
        logger.info(
            "Skip TTL tools because sql_dialect=%s (requires tree).",
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
    async def ttl_command(
        ttl_sql: str, confirm_unset: bool = False
    ) -> list[TextContent]:
        """Execute TTL command SQL.

        Supported prefixes:
        - SET TTL
        - UNSET TTL
        """
        session = None
        try:
            sql = _normalize_sql(ttl_sql)
            upper = sql.upper()
            if upper.startswith("SET TTL"):
                _assert_ttl_permission(config, action="SET")
            elif upper.startswith("UNSET TTL"):
                _assert_ttl_permission(
                    config, action="UNSET", confirm_unset=confirm_unset
                )
            else:
                raise ValueError(
                    "ttl_command only supports SQL starting with: SET TTL, UNSET TTL"
                )

            session = session_pool.get_session()
            session.execute_non_query_statement(sql)
            session.close()
            return [TextContent(type="text", text=f"Success: {sql}")]
        except Exception as e:
            if session:
                session.close()
            logger.error(f"Failed to execute ttl_command: {str(e)}")
            raise

    @mcp.tool()
    async def ttl_query(ttl_sql: str) -> list[TextContent]:
        """Execute TTL query SQL.

        Supported prefixes:
        - SHOW TTL ON
        - SHOW ALL TTL
        """
        session = None
        try:
            _assert_ttl_permission(config, action="SHOW")
            sql = _normalize_sql(ttl_sql)
            upper = sql.upper()
            if not upper.startswith(("SHOW TTL ON", "SHOW ALL TTL")):
                raise ValueError(
                    "ttl_query only supports SQL starting with: SHOW TTL ON, SHOW ALL TTL"
                )

            session = session_pool.get_session()
            res = session.execute_query_statement(sql)
            return _format_result(res, session)
        except Exception as e:
            if session:
                session.close()
            logger.error(f"Failed to execute ttl_query: {str(e)}")
            raise
