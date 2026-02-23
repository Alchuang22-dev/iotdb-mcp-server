import datetime
import logging
import os
import re
import uuid

from iotdb.Session import Session
from iotdb.SessionPool import PoolConfig, SessionPool
from iotdb.table_session import TableSession
from iotdb.table_session_pool import TableSessionPool, TableSessionPoolConfig
from iotdb.utils.SessionDataSet import SessionDataSet
from mcp.types import TextContent

from iotdb_mcp_server.config import Config


def sanitize_filename(filename: str, base_dir: str) -> str:
    """
    Sanitize and validate filename to prevent path traversal attacks.

    Security patch for CVE-2026-XXXXX
    Author: Mohammed Tanveer (threatpointer)
    Date: 2026-01-12

    Args:
        filename: The user-provided filename
        base_dir: The base directory for exports (must be absolute path)

    Returns:
        The sanitized absolute filepath

    Raises:
        ValueError: If the filename contains invalid characters or attempts path traversal

    Security measures:
    - Rejects any path separators or traversal sequences before processing
    - Validates allowed characters (alphanumeric, underscore, hyphen, dot)
    - Resolves absolute path and verifies it stays within base_dir boundary
    - Prevents directory traversal, symlink attacks, and path manipulation
    """
    if not filename:
        raise ValueError("Filename cannot be empty")

    if "/" in filename or "\\" in filename or ".." in filename:
        raise ValueError(
            "Invalid filename: path separators and directory traversal sequences are not allowed"
        )

    filename = os.path.basename(filename)

    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", filename):
        raise ValueError(
            "Invalid filename: only alphanumeric characters, underscore, hyphen, and dot are allowed"
        )

    if not filename or filename in (".", ".."):
        raise ValueError("Invalid filename")

    if filename.startswith(".."):
        raise ValueError("Invalid filename: cannot start with '..'")

    filepath = os.path.join(base_dir, filename)
    filepath_real = os.path.realpath(filepath)
    basedir_real = os.path.realpath(base_dir)

    if (
        not filepath_real.startswith(basedir_real + os.sep)
        and filepath_real != basedir_real
    ):
        raise ValueError("Path traversal detected: file must be within export directory")

    return filepath_real


def _ensure_export_directory(export_path: str, logger: logging.Logger) -> None:
    if os.path.exists(export_path):
        return
    try:
        os.makedirs(export_path)
        logger.info(f"Created export directory: {export_path}")
    except Exception as e:
        logger.warning(f"Failed to create export directory {export_path}: {str(e)}")


def _prepare_tree_res(_res: SessionDataSet, _session: Session) -> list[TextContent]:
    columns = _res.get_column_names()
    result = []
    while _res.has_next():
        record = _res.next()
        if columns[0] == "Time":
            timestamp = record.get_timestamp()
            row = record.get_fields()
            result.append(str(timestamp) + "," + ",".join(map(str, row)))
        else:
            row = record.get_fields()
            result.append(",".join(map(str, row)))
    _session.close()
    return [
        TextContent(
            type="text",
            text="\n".join([",".join(columns)] + result),
        )
    ]


def _prepare_table_res(
    _res: SessionDataSet, _table_session: TableSession
) -> list[TextContent]:
    columns = _res.get_column_names()
    result = []
    while _res.has_next():
        row = _res.next().get_fields()
        result.append(",".join(map(str, row)))
    _table_session.close()
    return [
        TextContent(
            type="text",
            text="\n".join([",".join(columns)] + result),
        )
    ]


def register_query_tools(mcp, config: Config, logger: logging.Logger) -> None:
    """Register query tools for the selected SQL dialect."""
    _ensure_export_directory(config.export_path, logger)
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
        wait_timeout_in_ms = 5000
        session_pool = SessionPool(pool_config, max_pool_size, wait_timeout_in_ms)

        @mcp.tool()
        async def select_query(query_sql: str) -> list[TextContent]:
            """Execute a SELECT query on the IoTDB tree SQL dialect.

            Args:
                query_sql: The SQL query to execute (using TREE dialect, time using ISO 8601 format, e.g. 2017-11-01T00:08:00.000).

            SQL Syntax:
                SELECT [LAST] selectExpr [, selectExpr] ...
                    [INTO intoItem [, intoItem] ...]
                    FROM prefixPath [, prefixPath] ...
                    [WHERE whereCondition]
                    [GROUP BY {
                        ([startTime, endTime), interval [, slidingStep]) |
                        LEVEL = levelNum [, levelNum] ... |
                        TAGS(tagKey [, tagKey] ... |
                        VARIATION(expression[,delta][,ignoreNull=true/false]) |
                        CONDITION(expression,[keep>/>=/=/</<=]threshold[,ignoreNull=true/false]) |
                        SESSION(timeInterval) |
                        COUNT(expression, size[,ignoreNull=true/false])
                    }]
                    [HAVING havingCondition]
                    [ORDER BY sortKey {ASC | DESC}]
                    [FILL ({PREVIOUS | LINEAR | constant}) (, interval=DURATION_LITERAL)?)]
                    [SLIMIT seriesLimit] [SOFFSET seriesOffset]
                    [LIMIT rowLimit] [OFFSET rowOffset]
                    [ALIGN BY {TIME | DEVICE}]

            Examples:
                select temperature from root.ln.wf01.wt01 where time < 2017-11-01T00:08:00.000
                select status, temperature from root.ln.wf01.wt01 where (time > 2017-11-01T00:05:00.000 and time < 2017-11-01T00:12:00.000) or (time >= 2017-11-01T16:35:00.000 and time <= 2017-11-01T16:37:00.000)
                select * from root.ln.** where time > 1 order by time desc limit 10;

            Supported Aggregate Functions:
                SUM
                COUNT
                MAX_VALUE
                MIN_VALUE
                AVG
                VARIANCE
                MAX_TIME
                MIN_TIME
                ...
            """
            session = None
            try:
                session = session_pool.get_session()
                stmt = query_sql.strip().upper()
                if stmt.startswith("SELECT"):
                    res = session.execute_query_statement(query_sql)
                    return _prepare_tree_res(res, session)
                session.close()
                raise ValueError("Only SELECT queries are allowed for select_query")
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to execute select query: {str(e)}")
                raise

        @mcp.tool()
        async def export_query(
            query_sql: str, format: str = "csv", filename: str = None
        ) -> list[TextContent]:
            """Execute a query and export the results to a CSV or Excel file.

            Args:
                query_sql: The SQL query to execute (using TREE dialect, time using ISO 8601 format, e.g. 2017-11-01T00:08:00.000)
                format: Export format, either "csv" or "excel" (default: "csv")
                filename: Optional filename for the exported file. If not provided, a unique filename will be generated.

            SQL Syntax:
                SELECT ⟨select_list⟩
                FROM ⟨tables⟩
                [WHERE ⟨condition⟩]
                [GROUP BY ⟨groups⟩]
                [HAVING ⟨group_filter⟩]
                [FILL ⟨fill_methods⟩]
                [ORDER BY ⟨order_expression⟩]
                [OFFSET ⟨n⟩]
                [LIMIT ⟨n⟩];

            Returns:
                Information about the exported file and a preview of the data (max 10 rows)
            """
            session = None
            try:
                session = session_pool.get_session()
                stmt = query_sql.strip().upper()
                if not (stmt.startswith("SELECT") or stmt.startswith("SHOW")):
                    raise ValueError("Only SELECT or SHOW queries are allowed for export")

                res = session.execute_query_statement(query_sql)
                df = res.todf()
                session.close()

                timestamp = int(datetime.datetime.now().timestamp())
                if filename is None:
                    filename = f"dump_{uuid.uuid4().hex[:4]}_{timestamp}"

                if format.lower() == "csv":
                    if filename.lower().endswith(".csv"):
                        filename = filename[:-4]
                    filepath = sanitize_filename(f"{filename}.csv", config.export_path)
                    df.to_csv(filepath, index=False)
                elif format.lower() == "excel":
                    if filename.lower().endswith(".xlsx"):
                        filename = filename[:-5]
                    filepath = sanitize_filename(f"{filename}.xlsx", config.export_path)
                    df.to_excel(filepath, index=False)
                else:
                    raise ValueError("Format must be either 'csv' or 'excel'")

                preview_rows = min(10, len(df))
                preview_data = [",".join(df.columns)]
                for i in range(preview_rows):
                    preview_data.append(",".join(map(str, df.iloc[i])))

                return [
                    TextContent(
                        type="text",
                        text=f"Query results exported to {filepath}\n\nPreview (first {preview_rows} rows):\n"
                        + "\n".join(preview_data),
                    )
                ]
            except Exception as e:
                if session:
                    session.close()
                logger.error(f"Failed to export query: {str(e)}")
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
        async def read_query(query_sql: str) -> list[TextContent]:
            """Execute a SELECT query on the IoTDB. Please use table sql_dialect when generating SQL queries.

            Args:
                query_sql: The SQL query to execute (using TABLE dialect, time using ISO 8601 format, e.g. 2017-11-01T00:08:00.000)
            """
            table_session = None
            try:
                table_session = session_pool.get_session()
                stmt = query_sql.strip().upper()
                if (
                    stmt.startswith("SELECT")
                    or stmt.startswith("DESCRIBE")
                    or stmt.startswith("SHOW")
                ):
                    res = table_session.execute_query_statement(query_sql)
                    return _prepare_table_res(res, table_session)
                table_session.close()
                raise ValueError("Only SELECT queries are allowed for read_query")
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to execute query: {str(e)}")
                raise

        @mcp.tool()
        async def export_table_query(
            query_sql: str, format: str = "csv", filename: str = None
        ) -> list[TextContent]:
            """Execute a query and export the results to a CSV or Excel file.

            Args:
                query_sql: The SQL query to execute (using TABLE dialect, time using ISO 8601 format, e.g. 2017-11-01T00:08:00.000)
                format: Export format, either "csv" or "excel" (default: "csv")
                filename: Optional filename for the exported file. If not provided, a unique filename will be generated.

            SQL Syntax:
                SELECT ⟨select_list⟩
                FROM ⟨tables⟩
                [WHERE ⟨condition⟩]
                [GROUP BY ⟨groups⟩]
                [HAVING ⟨group_filter⟩]
                [FILL ⟨fill_methods⟩]
                [ORDER BY ⟨order_expression⟩]
                [OFFSET ⟨n⟩]
                [LIMIT ⟨n⟩];

            Returns:
                Information about the exported file and a preview of the data (max 10 rows)
            """
            table_session = None
            try:
                table_session = session_pool.get_session()
                stmt = query_sql.strip().upper()
                if not (
                    stmt.startswith("SELECT")
                    or stmt.startswith("SHOW")
                    or stmt.startswith("DESCRIBE")
                    or stmt.startswith("DESC")
                ):
                    raise ValueError(
                        "Only SELECT, SHOW or DESCRIBE queries are allowed for export"
                    )

                res = table_session.execute_query_statement(query_sql)
                df = res.todf()
                table_session.close()

                timestamp = int(datetime.datetime.now().timestamp())
                if filename is None:
                    filename = f"dump_{uuid.uuid4().hex[:4]}_{timestamp}"

                if format.lower() == "csv":
                    if filename.lower().endswith(".csv"):
                        filename = filename[:-4]
                    filepath = sanitize_filename(f"{filename}.csv", config.export_path)
                    df.to_csv(filepath, index=False)
                elif format.lower() == "excel":
                    if filename.lower().endswith(".xlsx"):
                        filename = filename[:-5]
                    filepath = sanitize_filename(f"{filename}.xlsx", config.export_path)
                    df.to_excel(filepath, index=False)
                else:
                    raise ValueError("Format must be either 'csv' or 'excel'")

                preview_rows = min(10, len(df))
                preview_data = [",".join(df.columns)]
                for i in range(preview_rows):
                    preview_data.append(",".join(map(str, df.iloc[i])))

                return [
                    TextContent(
                        type="text",
                        text=f"Query results exported to {filepath}\n\nPreview (first {preview_rows} rows):\n"
                        + "\n".join(preview_data),
                    )
                ]
            except Exception as e:
                if table_session:
                    table_session.close()
                logger.error(f"Failed to export table query: {str(e)}")
                raise

    else:
        raise ValueError(
            f"Unsupported sql_dialect '{config.sql_dialect}'. Expected 'tree' or 'table'."
        )
