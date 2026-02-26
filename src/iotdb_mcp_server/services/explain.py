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

from iotdb.Session import Session
from iotdb.SessionPool import PoolConfig, SessionPool
from iotdb.table_session import TableSession
from iotdb.table_session_pool import TableSessionPool, TableSessionPoolConfig
from iotdb.utils.SessionDataSet import SessionDataSet
from mcp.types import TextContent

from iotdb_mcp_server.config import Config
from iotdb_mcp_server.services.json_response import payload_response


def _collect_result(
    res: SessionDataSet, session_or_table_session: Session | TableSession
) -> tuple[list[str], list[str]]:
    columns = res.get_column_names()
    rows: list[str] = []
    while res.has_next():
        row = res.next().get_fields()
        rows.append(",".join(map(str, row)))
    session_or_table_session.close()
    return columns, rows


def _normalize_and_validate_sql(
    sql_dialect: str, sql: str, analyze: bool
) -> tuple[str, str]:
    raw_sql = sql.strip()
    if not raw_sql:
        raise ValueError("SQL cannot be empty")

    explain_sql = raw_sql
    upper = raw_sql.upper()

    if not upper.startswith("EXPLAIN"):
        explain_prefix = "EXPLAIN ANALYZE " if analyze else "EXPLAIN "
        explain_sql = explain_prefix + raw_sql
        target_sql = raw_sql.strip()
    else:
        # Accept user-provided EXPLAIN; do not override existing options.
        target_sql = raw_sql[len("EXPLAIN") :].strip()
        if target_sql.upper().startswith("ANALYZE"):
            target_sql = target_sql[len("ANALYZE") :].strip()

    target_upper = target_sql.upper()
    allowed_prefixes = (
        ("SELECT", "SHOW", "COUNT", "WITH")
        if sql_dialect == "tree"
        else ("SELECT", "SHOW", "DESC", "DESCRIBE", "WITH")
    )

    if not target_upper.startswith(allowed_prefixes):
        raise ValueError(
            f"explain_query only supports query-like SQL for {sql_dialect} dialect. "
            f"Allowed prefixes: {', '.join(allowed_prefixes)}"
        )

    return explain_sql, target_sql


def register_explain_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register EXPLAIN tool for the selected SQL dialect."""
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
        async def explain_query(query_sql: str, analyze: bool = False) -> list[TextContent]:
            """Execute EXPLAIN SQL and return the plan so LLM can review generated SQL.

            Args:
                query_sql: SQL to be explained. You can pass raw query SQL or an EXPLAIN SQL.
                analyze: When True and query_sql is not already EXPLAIN, uses EXPLAIN ANALYZE.
            """
            session = None
            try:
                explain_sql, _ = _normalize_and_validate_sql(
                    config.sql_dialect, query_sql, analyze
                )
                session = session_pool.get_session()
                res = session.execute_query_statement(explain_sql)
                columns, rows = _collect_result(res, session)
                return payload_response(
                    "explain_query",
                    {
                        "explain_sql": explain_sql,
                        "plan": {
                            "format": "csv",
                            "columns": columns,
                            "rows": rows,
                            "text": "\n".join([",".join(columns)] + rows),
                        },
                    },
                    message="Explain executed.",
                )
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to execute explain query: {str(e)}")
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
        async def explain_query(query_sql: str, analyze: bool = False) -> list[TextContent]:
            """Execute EXPLAIN SQL and return the plan so LLM can review generated SQL.

            Args:
                query_sql: SQL to be explained. You can pass raw query SQL or an EXPLAIN SQL.
                analyze: When True and query_sql is not already EXPLAIN, uses EXPLAIN ANALYZE.
            """
            table_session = None
            try:
                explain_sql, _ = _normalize_and_validate_sql(
                    config.sql_dialect, query_sql, analyze
                )
                table_session = session_pool.get_session()
                res = table_session.execute_query_statement(explain_sql)
                columns, rows = _collect_result(res, table_session)
                return payload_response(
                    "explain_query",
                    {
                        "explain_sql": explain_sql,
                        "plan": {
                            "format": "csv",
                            "columns": columns,
                            "rows": rows,
                            "text": "\n".join([",".join(columns)] + rows),
                        },
                    },
                    message="Explain executed.",
                )
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to execute explain query: {str(e)}")
                raise
    else:
        raise ValueError(
            f"Unsupported sql_dialect '{config.sql_dialect}'. Expected 'tree' or 'table'."
        )
