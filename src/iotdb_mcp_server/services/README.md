# IoTDB MCP Services

This directory contains tool modules registered by `src/iotdb_mcp_server/server.py`.

## Registration Overview

Current registration order:

1. `register_query_tools`
2. `register_sql_driver_tools`
3. `register_metadata_tools`
4. `register_explain_tools`
5. `register_database_tools`
6. `register_timeseries_tools`
7. `register_ttl_tools`
8. `register_table_tools`
9. `register_write_tools`
10. `register_model_tools`

## Tool Matrix

### `query.py`

- Tree dialect:
  - `select_query(query_sql)`
  - `export_query(query_sql, format="csv", filename=None)`
- Table dialect:
  - `read_query(query_sql)`
  - `export_table_query(query_sql, format="csv", filename=None)`

### `sql_driver.py`

- Both dialects:
  - `sql_driver_policy()`
  - `sql_execute(sql, confirm_destructive=False)`

Features:

- Statement whitelist by category: `readonly` / `ddl` / `full`
- Mode-based permissions via `IOTDB_SQL_DRIVER_MODE`
- Destructive SQL confirmation policy
- Tree CQ enabled in whitelist:
  - Readonly: `SHOW CONTINUOUS QUERIES`, `SHOW CQS`
  - DDL: `CREATE CONTINUOUS QUERY` / `CREATE CQ`, `DROP CONTINUOUS QUERY` / `DROP CQ`
- Downsampling execution path:
  - ad-hoc: `SELECT ... GROUP BY ([start, end), interval[, slidingStep])`
  - scheduled: CQ with `INTO` + optional `RESAMPLE` clause

### `metadata.py`

- Tree dialect:
  - `metadata_query(query_sql)`
  - `list_timeseries(path="root.**")`
  - `list_devices(path="root.**")`
  - `list_child_paths(path)`
  - `list_child_nodes(path)`
  - `count_timeseries(path="root.**")`
  - `count_devices(path="root.**")`
  - `count_nodes(path="root")`
- Table dialect:
  - `metadata_query(query_sql)`
  - `list_tables()`
  - `describe_table(table_name, details=True)`

### `explain.py`

- Both dialects:
  - `explain_query(query_sql, analyze=False)`

### `database.py`

- Tree dialect:
  - `list_databases(details=False)`
  - `create_database(database)`
  - `drop_database(database, confirm=False)`
- Table dialect:
  - `list_databases(details=False)`
  - `create_database(database, if_not_exists=True)`
  - `drop_database(database, if_exists=True, confirm=False)`
  - `use_database(database)`

### `timeseries.py` (tree only)

- `create_timeseries_ddl(ddl_sql)`
- `alter_timeseries_ddl(ddl_sql)`
- `drop_timeseries_ddl(ddl_sql, confirm=False)`

### `ttl.py` (tree only)

- `ttl_command(ttl_sql, confirm_unset=False)`
- `ttl_query(ttl_sql)`

### `table.py` (table only)

- `create_table_ddl(ddl_sql)`
- `alter_table_ddl(ddl_sql)`
- `drop_table_ddl(ddl_sql, confirm=False)`

### `write.py`

- Tree dialect:
  - `write_query(write_sql, confirm_delete=False)` (INSERT/DELETE)
- Table dialect:
  - `write_query(write_sql, confirm_delete=False)` (INSERT/UPDATE/DELETE)

### `model.py`

- Both dialects:
  - `model_query(model_sql)`
  - `model_command(model_sql, confirm_destructive=False)`

## Security and Permission Gates

Most write/DDL/model tools are disabled by default and require env flags.

### Per-module gates

- `database.py`
  - `IOTDB_ENABLE_DATABASE_DDL`
  - `IOTDB_DATABASE_DDL_ALLOWED_USERS`
  - `IOTDB_REQUIRE_DROP_CONFIRM`
- `timeseries.py`
  - `IOTDB_ENABLE_TIMESERIES_DDL`
  - `IOTDB_TIMESERIES_DDL_ALLOWED_USERS`
  - `IOTDB_REQUIRE_TIMESERIES_DROP_CONFIRM`
- `table.py`
  - `IOTDB_ENABLE_TABLE_DDL`
  - `IOTDB_TABLE_DDL_ALLOWED_USERS`
  - `IOTDB_REQUIRE_TABLE_DROP_CONFIRM`
- `ttl.py`
  - `IOTDB_ENABLE_TTL_SQL`
  - `IOTDB_TTL_ALLOWED_USERS`
  - `IOTDB_REQUIRE_TTL_UNSET_CONFIRM`
- `write.py`
  - `IOTDB_ENABLE_WRITE_DML`
  - `IOTDB_WRITE_ALLOWED_USERS`
  - `IOTDB_REQUIRE_DELETE_CONFIRM`
- `model.py`
  - `IOTDB_ENABLE_MODEL_MANAGEMENT`
  - `IOTDB_MODEL_ALLOWED_USERS`
  - `IOTDB_REQUIRE_MODEL_DESTRUCTIVE_CONFIRM`
- `metadata.py`
  - `IOTDB_ENABLE_METADATA_QUERY`
  - `IOTDB_METADATA_ALLOWED_USERS`
- `sql_driver.py`
  - `IOTDB_ENABLE_SQL_DRIVER`
  - `IOTDB_SQL_DRIVER_ALLOWED_USERS`
  - `IOTDB_SQL_DRIVER_MODE` (`readonly` / `ddl` / `full`)
  - `IOTDB_SQL_DRIVER_REQUIRE_DESTRUCTIVE_CONFIRM`
  - `IOTDB_SQL_DRIVER_EXTRA_READONLY_PREFIXES`
  - `IOTDB_SQL_DRIVER_EXTRA_DDL_PREFIXES`
  - `IOTDB_SQL_DRIVER_EXTRA_FULL_PREFIXES`

## Minimal Enablement Example

```bash
# Dialect
IOTDB_SQL_DIALECT=tree

# Keep generic driver available in ddl mode
IOTDB_ENABLE_SQL_DRIVER=true
IOTDB_SQL_DRIVER_MODE=ddl
IOTDB_SQL_DRIVER_ALLOWED_USERS=root

# Enable selected specialized tools
IOTDB_ENABLE_METADATA_QUERY=true
IOTDB_ENABLE_DATABASE_DDL=true
IOTDB_ENABLE_TIMESERIES_DDL=true
IOTDB_ENABLE_TTL_SQL=true
IOTDB_ENABLE_WRITE_DML=true
IOTDB_ENABLE_MODEL_MANAGEMENT=true
```

## Notes

- All tools enforce single-statement execution (`;` separated multi-statement is rejected).
- Tool availability depends on `sql_dialect` (`tree` or `table`).
- For production, prefer least privilege:
  - keep `IOTDB_SQL_DRIVER_MODE=readonly` unless workflow needs writes,
  - use strict `*_ALLOWED_USERS`,
  - keep destructive confirm flags enabled.
