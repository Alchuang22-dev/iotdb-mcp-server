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
from iotdb_mcp_server.services.json_response import csv_payload_response

_TREE_PATH_PATTERN = re.compile(r"^root(?:\.[A-Za-z_][A-Za-z0-9_]*|\.\*|\.\*\*)*$")
_TABLE_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _csv_set(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def _assert_metadata_permission(config: Config) -> None:
    if not _env_bool("IOTDB_ENABLE_METADATA_QUERY", True):
        raise PermissionError(
            "Metadata tools are disabled by server policy. "
            "Set IOTDB_ENABLE_METADATA_QUERY=true to enable."
        )

    allowed_users = _csv_set(os.getenv("IOTDB_METADATA_ALLOWED_USERS", "*"))
    if "*" not in allowed_users and config.user not in allowed_users:
        raise PermissionError(
            f"Current MCP user '{config.user}' is not allowed by IOTDB_METADATA_ALLOWED_USERS."
        )


def _normalize_sql(sql: str) -> str:
    cleaned = sql.strip()
    if not cleaned:
        raise ValueError("Metadata SQL cannot be empty.")
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if ";" in cleaned:
        raise ValueError("Only a single SQL statement is allowed.")
    return cleaned


def _validate_tree_path(path: str) -> str:
    cleaned = path.strip()
    if not cleaned:
        raise ValueError("Tree path cannot be empty.")
    if not _TREE_PATH_PATTERN.fullmatch(cleaned):
        raise ValueError(
            "Invalid tree path. Use path like root.sg, root.sg.dev, root.**, root.sg.*"
        )
    return cleaned


def _validate_table_identifier(identifier: str) -> str:
    cleaned = identifier.strip()
    if not _TABLE_IDENTIFIER_PATTERN.fullmatch(cleaned):
        raise ValueError(
            "Invalid table identifier. Use letters, numbers, and underscore only."
        )
    return cleaned


def _format_result(
    res: SessionDataSet,
    session_or_table_session: Session | TableSession,
    tool_name: str,
) -> list[TextContent]:
    columns = res.get_column_names()
    rows: list[str] = []
    while res.has_next():
        row = res.next().get_fields()
        rows.append(",".join(map(str, row)))
    session_or_table_session.close()
    return csv_payload_response(tool_name, columns, rows)


def _ensure_prefix(sql: str, allowed_prefixes: tuple[str, ...], action_name: str) -> None:
    upper = sql.upper()
    if not upper.startswith(allowed_prefixes):
        raise ValueError(
            f"{action_name} only supports SQL starting with: {', '.join(allowed_prefixes)}"
        )


def register_metadata_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register metadata tools for tree/table sql dialect."""
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
        tree_prefixes = (
            "SHOW DATABASES",
            "SHOW TIMESERIES",
            "SHOW DEVICES",
            "SHOW CHILD PATHS",
            "SHOW CHILD NODES",
            "SHOW FUNCTIONS",
            "COUNT TIMESERIES",
            "COUNT NODES",
            "COUNT DEVICES",
        )

        @mcp.tool()
        async def metadata_query(query_sql: str) -> list[TextContent]:
            """Execute tree-model metadata SQL."""
            session = None
            try:
                _assert_metadata_permission(config)
                sql = _normalize_sql(query_sql)
                _ensure_prefix(sql, tree_prefixes, "metadata_query")
                session = session_pool.get_session()
                res = session.execute_query_statement(sql)
                return _format_result(res, session, "metadata_query")
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to execute metadata_query: {str(e)}")
                raise

        @mcp.tool()
        async def list_timeseries(path: str = "root.**") -> list[TextContent]:
            """List timeseries under a tree path pattern."""
            query_sql = f"SHOW TIMESERIES {_validate_tree_path(path)}"
            return await metadata_query(query_sql)

        @mcp.tool()
        async def list_devices(path: str = "root.**") -> list[TextContent]:
            """List devices under a tree path pattern."""
            query_sql = f"SHOW DEVICES {_validate_tree_path(path)}"
            return await metadata_query(query_sql)

        @mcp.tool()
        async def list_child_paths(path: str) -> list[TextContent]:
            """List child paths under a tree path."""
            query_sql = f"SHOW CHILD PATHS {_validate_tree_path(path)}"
            return await metadata_query(query_sql)

        @mcp.tool()
        async def list_child_nodes(path: str) -> list[TextContent]:
            """List child nodes under a tree path."""
            query_sql = f"SHOW CHILD NODES {_validate_tree_path(path)}"
            return await metadata_query(query_sql)

        @mcp.tool()
        async def count_timeseries(path: str = "root.**") -> list[TextContent]:
            """Count timeseries under a tree path pattern."""
            query_sql = f"COUNT TIMESERIES {_validate_tree_path(path)}"
            return await metadata_query(query_sql)

        @mcp.tool()
        async def count_devices(path: str = "root.**") -> list[TextContent]:
            """Count devices under a tree path pattern."""
            query_sql = f"COUNT DEVICES {_validate_tree_path(path)}"
            return await metadata_query(query_sql)

        @mcp.tool()
        async def count_nodes(path: str = "root") -> list[TextContent]:
            """Count nodes under a tree path."""
            query_sql = f"COUNT NODES {_validate_tree_path(path)}"
            return await metadata_query(query_sql)

    elif config.sql_dialect == "table":
        session_pool_config = TableSessionPoolConfig(
            node_urls=[str(config.host) + ":" + str(config.port)],
            username=config.user,
            password=config.password,
            max_pool_size=max_pool_size,
            database=None if len(config.database) == 0 else config.database,
        )
        session_pool = TableSessionPool(session_pool_config)
        table_prefixes = ("SHOW", "DESC", "DESCRIBE")

        @mcp.tool()
        async def metadata_query(query_sql: str) -> list[TextContent]:
            """Execute table-model metadata SQL."""
            table_session = None
            try:
                _assert_metadata_permission(config)
                sql = _normalize_sql(query_sql)
                _ensure_prefix(sql, table_prefixes, "metadata_query")
                table_session = session_pool.get_session()
                res = table_session.execute_query_statement(sql)
                return _format_result(res, table_session, "metadata_query")
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to execute metadata_query: {str(e)}")
                raise

        @mcp.tool()
        async def list_tables() -> list[TextContent]:
            """List all tables in current table-model database."""
            return await metadata_query("SHOW TABLES")

        @mcp.tool()
        async def describe_table(
            table_name: str, details: bool = True
        ) -> list[TextContent]:
            """Describe schema for a table in current table-model database."""
            safe_table = _validate_table_identifier(table_name)
            details_suffix = " details" if details else ""
            return await metadata_query(f"DESC {safe_table}{details_suffix}")

    else:
        raise ValueError(
            f"Unsupported sql_dialect '{config.sql_dialect}'. Expected 'tree' or 'table'."
        )
