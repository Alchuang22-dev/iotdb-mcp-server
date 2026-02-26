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
from iotdb_mcp_server.services.json_response import (
    csv_payload_response,
    payload_response,
)

_READONLY_PREFIXES_COMMON = (
    "SELECT",
    "SHOW",
    "EXPLAIN",
    "DESC",
    "DESCRIBE",
 )
_READONLY_PREFIXES_TREE = (
    "COUNT TIMESERIES",
    "COUNT NODES",
    "COUNT DEVICES",
    "CALL INFERENCE",
    "SHOW CONTINUOUS QUERIES",
    "SHOW CQS",
)
_READONLY_PREFIXES_TABLE: tuple[str, ...] = ()

_DDL_PREFIXES_COMMON = (
    "CREATE DATABASE",
    "ALTER DATABASE",
    "DROP DATABASE",
    "CREATE TABLE",
    "ALTER TABLE",
    "DROP TABLE",
    "USE",
    "SET TTL",
    "UNSET TTL",
    "CREATE MODEL",
    "DROP MODEL",
    "LOAD MODEL",
    "UNLOAD MODEL",
    "REMOVE AINODE",
)
_DDL_PREFIXES_TREE = (
    "CREATE TIMESERIES",
    "CREATE ALIGNED TIMESERIES",
    "ALTER TIMESERIES",
    "DROP TIMESERIES",
    "DELETE TIMESERIES",
    "CREATE CONTINUOUS QUERY",
    "CREATE CQ",
    "DROP CONTINUOUS QUERY",
    "DROP CQ",
)
_DDL_PREFIXES_TABLE: tuple[str, ...] = ()

_FULL_PREFIXES_COMMON = (
    "INSERT INTO",
    "UPDATE",
    "DELETE FROM",
    "DELETE DEVICES",
)
_FULL_PREFIXES_TREE: tuple[str, ...] = ()
_FULL_PREFIXES_TABLE: tuple[str, ...] = ()

_DESTRUCTIVE_PREFIXES = (
    "DROP ",
    "DELETE ",
    "UNSET TTL",
    "REMOVE AINODE",
    "UNLOAD MODEL",
)


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _parse_mode() -> str:
    mode = os.getenv("IOTDB_SQL_DRIVER_MODE", "readonly").strip().lower()
    if mode not in ("readonly", "ddl", "full"):
        raise ValueError(
            "Invalid IOTDB_SQL_DRIVER_MODE. Expected one of: readonly, ddl, full."
        )
    return mode


def _normalize_sql(sql: str) -> str:
    cleaned = sql.strip()
    if not cleaned:
        raise ValueError("SQL cannot be empty.")
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if ";" in cleaned:
        raise ValueError("Only a single SQL statement is allowed.")
    return cleaned


def _normalize_for_prefix(sql: str) -> str:
    return re.sub(r"\s+", " ", sql).strip().upper()


def _merge_prefixes(base: tuple[str, ...], env_var: str) -> tuple[str, ...]:
    extra = tuple(
        item.strip().upper()
        for item in os.getenv(env_var, "").split(",")
        if item.strip()
    )
    all_prefixes = tuple(dict.fromkeys([*base, *extra]))
    return tuple(sorted(all_prefixes, key=len, reverse=True))


def _resolve_whitelists(sql_dialect: str) -> dict[str, tuple[str, ...]]:
    readonly = (
        _READONLY_PREFIXES_COMMON
        + (_READONLY_PREFIXES_TREE if sql_dialect == "tree" else _READONLY_PREFIXES_TABLE)
    )
    ddl = _DDL_PREFIXES_COMMON + (_DDL_PREFIXES_TREE if sql_dialect == "tree" else _DDL_PREFIXES_TABLE)
    full = _FULL_PREFIXES_COMMON + (_FULL_PREFIXES_TREE if sql_dialect == "tree" else _FULL_PREFIXES_TABLE)

    return {
        "readonly": _merge_prefixes(readonly, "IOTDB_SQL_DRIVER_EXTRA_READONLY_PREFIXES"),
        "ddl": _merge_prefixes(ddl, "IOTDB_SQL_DRIVER_EXTRA_DDL_PREFIXES"),
        "full": _merge_prefixes(full, "IOTDB_SQL_DRIVER_EXTRA_FULL_PREFIXES"),
    }


def _classify_sql(sql: str, whitelists: dict[str, tuple[str, ...]]) -> tuple[str, str]:
    normalized_upper = _normalize_for_prefix(sql)

    for category in ("readonly", "ddl", "full"):
        for prefix in whitelists[category]:
            if normalized_upper.startswith(prefix):
                return category, prefix

    raise ValueError(
        "SQL is not in whitelist. Allowed categories and prefixes can be inspected "
        "with sql_driver_policy tool."
    )


def _is_destructive_prefix(prefix: str) -> bool:
    upper_prefix = prefix.upper()
    return upper_prefix.startswith(_DESTRUCTIVE_PREFIXES)


def _assert_sql_driver_permission(
    config: Config,
    required_category: str,
    mode: str,
    confirm_destructive: bool,
    matched_prefix: str,
) -> None:
    if not _env_bool("IOTDB_ENABLE_SQL_DRIVER", False):
        raise PermissionError(
            "SQL driver tool is disabled by server policy. "
            "Set IOTDB_ENABLE_SQL_DRIVER=true to enable."
        )

    allowed_users = _csv_set(os.getenv("IOTDB_SQL_DRIVER_ALLOWED_USERS", "root"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_SQL_DRIVER_ALLOWED_USERS."
        )

    if required_category == "ddl" and mode == "readonly":
        raise PermissionError(
            f"Current sql driver mode '{mode}' does not allow DDL SQL ('{matched_prefix}')."
        )
    if required_category == "full" and mode in ("readonly", "ddl"):
        raise PermissionError(
            f"Current sql driver mode '{mode}' does not allow DML SQL ('{matched_prefix}')."
        )

    if (
        _is_destructive_prefix(matched_prefix)
        and _env_bool("IOTDB_SQL_DRIVER_REQUIRE_DESTRUCTIVE_CONFIRM", True)
        and not confirm_destructive
    ):
        raise PermissionError(
            "Destructive SQL requires confirm_destructive=True by server policy."
        )


def _format_tree_result(
    res: SessionDataSet, session: Session, tool_name: str
) -> list[TextContent]:
    columns = res.get_column_names()
    rows: list[str] = []
    while res.has_next():
        record = res.next()
        if columns and columns[0] == "Time":
            timestamp = record.get_timestamp()
            row = record.get_fields()
            rows.append(str(timestamp) + "," + ",".join(map(str, row)))
        else:
            rows.append(",".join(map(str, record.get_fields())))
    session.close()
    return csv_payload_response(tool_name, columns, rows)


def _format_table_result(
    res: SessionDataSet, table_session: TableSession, tool_name: str
) -> list[TextContent]:
    columns = res.get_column_names()
    rows: list[str] = []
    while res.has_next():
        rows.append(",".join(map(str, res.next().get_fields())))
    table_session.close()
    return csv_payload_response(tool_name, columns, rows)


def register_sql_driver_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register generic SQL execution tools with whitelist + mode gating."""
    mode = _parse_mode()
    whitelists = _resolve_whitelists(config.sql_dialect)
    logger.info("SQL driver mode=%s for dialect=%s", mode, config.sql_dialect)

    @mcp.tool()
    async def sql_driver_policy() -> list[TextContent]:
        """Show current sql_driver policy and statement whitelists."""
        return payload_response(
            "sql_driver_policy",
            {
                "sql_dialect": config.sql_dialect,
                "mode": mode,
                "enable_sql_driver": _env_bool("IOTDB_ENABLE_SQL_DRIVER", False),
                "require_destructive_confirm": _env_bool(
                    "IOTDB_SQL_DRIVER_REQUIRE_DESTRUCTIVE_CONFIRM", True
                ),
                "whitelists": whitelists,
            },
            message="SQL driver policy snapshot.",
        )

    if config.sql_dialect == "tree":
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
        async def sql_execute(
            sql: str, confirm_destructive: bool = False
        ) -> list[TextContent]:
            """Execute one tree-model SQL statement with whitelist + mode permission.

            Modes:
            - readonly: only readonly whitelist
            - ddl: readonly + ddl whitelist
            - full: readonly + ddl + full whitelist
            """
            session = None
            try:
                normalized_sql = _normalize_sql(sql)
                category, matched_prefix = _classify_sql(normalized_sql, whitelists)
                _assert_sql_driver_permission(
                    config,
                    required_category=category,
                    mode=mode,
                    confirm_destructive=confirm_destructive,
                    matched_prefix=matched_prefix,
                )

                session = session_pool.get_session()
                if category == "readonly":
                    res = session.execute_query_statement(normalized_sql)
                    return _format_tree_result(res, session, "sql_execute")

                session.execute_non_query_statement(normalized_sql)
                session.close()
                return payload_response(
                    "sql_execute",
                    {
                        "sql": normalized_sql,
                        "category": category,
                        "mode": mode,
                        "matched_prefix": matched_prefix,
                        "result": "success",
                    },
                    message="SQL executed successfully.",
                )
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to execute sql_execute (tree): {str(e)}")
                raise

    elif config.sql_dialect == "table":
        session_pool_config = TableSessionPoolConfig(
            node_urls=[str(config.host) + ":" + str(config.port)],
            username=config.user,
            password=config.password,
            max_pool_size=100,
            database=None if len(config.database) == 0 else config.database,
        )
        session_pool = TableSessionPool(session_pool_config)

        @mcp.tool()
        async def sql_execute(
            sql: str, confirm_destructive: bool = False
        ) -> list[TextContent]:
            """Execute one table-model SQL statement with whitelist + mode permission.

            Modes:
            - readonly: only readonly whitelist
            - ddl: readonly + ddl whitelist
            - full: readonly + ddl + full whitelist
            """
            table_session = None
            try:
                normalized_sql = _normalize_sql(sql)
                category, matched_prefix = _classify_sql(normalized_sql, whitelists)
                _assert_sql_driver_permission(
                    config,
                    required_category=category,
                    mode=mode,
                    confirm_destructive=confirm_destructive,
                    matched_prefix=matched_prefix,
                )

                table_session = session_pool.get_session()
                if category == "readonly":
                    res = table_session.execute_query_statement(normalized_sql)
                    return _format_table_result(res, table_session, "sql_execute")

                table_session.execute_non_query_statement(normalized_sql)
                table_session.close()
                return payload_response(
                    "sql_execute",
                    {
                        "sql": normalized_sql,
                        "category": category,
                        "mode": mode,
                        "matched_prefix": matched_prefix,
                        "result": "success",
                    },
                    message="SQL executed successfully.",
                )
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to execute sql_execute (table): {str(e)}")
                raise
    else:
        raise ValueError(
            f"Unsupported sql_dialect '{config.sql_dialect}'. Expected 'tree' or 'table'."
        )
