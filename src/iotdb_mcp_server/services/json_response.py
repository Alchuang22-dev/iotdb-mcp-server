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

import json
from datetime import datetime, timezone
from typing import Any

from mcp.types import TextContent

_RESPONSE_VERSION = "1.0"


class JsonParser:
    """Simple parser/checker for MCP tool JSON envelopes."""

    _required_keys = ("version", "tool", "ok", "timestamp", "payload")

    @staticmethod
    def check_format(obj: Any) -> bool:
        if not isinstance(obj, dict):
            return False
        for key in JsonParser._required_keys:
            if key not in obj:
                return False
        if not isinstance(obj["version"], str):
            return False
        if not isinstance(obj["tool"], str) or not obj["tool"].strip():
            return False
        if not isinstance(obj["ok"], bool):
            return False
        if not isinstance(obj["timestamp"], str) or not obj["timestamp"].strip():
            return False
        return True

    @staticmethod
    def parse(text: str) -> dict[str, Any]:
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON text: {e.msg}") from e

        if not JsonParser.check_format(obj):
            raise ValueError(
                "Invalid wrapped response format. Expected keys: "
                "version, tool, ok, timestamp, payload."
            )
        return obj


def _envelope(
    tool: str, payload: Any, ok: bool = True, message: str | None = None
) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "version": _RESPONSE_VERSION,
        "tool": tool,
        "ok": ok,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload": payload,
    }
    if message is not None:
        obj["message"] = message
    return obj


def _to_text_content(obj: dict[str, Any]) -> list[TextContent]:
    if not JsonParser.check_format(obj):
        raise ValueError("JsonParser format check failed before output.")
    text = json.dumps(obj, ensure_ascii=False)
    JsonParser.parse(text)
    return [TextContent(type="text", text=text)]


def payload_response(
    tool: str, payload: Any, message: str | None = None
) -> list[TextContent]:
    return _to_text_content(_envelope(tool=tool, payload=payload, message=message))


def text_payload_response(
    tool: str, text: str, message: str | None = None
) -> list[TextContent]:
    return payload_response(
        tool=tool,
        payload={"format": "text", "text": text},
        message=message,
    )


def csv_payload_response(
    tool: str, columns: list[str], rows: list[str], message: str | None = None
) -> list[TextContent]:
    csv_text = "\n".join([",".join(columns)] + rows)
    return payload_response(
        tool=tool,
        payload={
            "format": "csv",
            "columns": columns,
            "rows": rows,
            "text": csv_text,
        },
        message=message,
    )


def sql_success_response(tool: str, sql: str) -> list[TextContent]:
    return payload_response(
        tool=tool,
        payload={"sql": sql, "result": "success"},
        message="SQL executed successfully.",
    )
