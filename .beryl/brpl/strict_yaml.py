"""Strict data-only YAML subset used by BRPL policy files.

The parser intentionally accepts only the small block-style subset BRPL needs:
plain mappings, sequences, strings, booleans, integers, and null. It rejects
multi-document streams, tabs, flow collections, anchors, aliases, and tags.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


class StrictYAMLError(ValueError):
    pass


@dataclass(frozen=True)
class _Line:
    number: int
    indent: int
    text: str


_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


def load_strict_yaml(text: str, *, max_lines: int | None = None, max_nesting: int | None = None) -> Any:
    lines = _prepare_lines(text, max_lines=max_lines)
    if not lines:
        raise StrictYAMLError("policy must not be empty")
    value, index = _parse_block(lines, 0, lines[0].indent, max_nesting=max_nesting, depth=1)
    if index != len(lines):
        line = lines[index]
        raise StrictYAMLError(f"unexpected trailing content at line {line.number}")
    return value


def _prepare_lines(text: str, *, max_lines: int | None = None) -> list[_Line]:
    prepared: list[_Line] = []
    if "\0" in text:
        raise StrictYAMLError("NUL bytes are not allowed")
    for number, raw in enumerate(text.splitlines(), start=1):
        if max_lines is not None and number > max_lines:
            raise StrictYAMLError(f"policy exceeds {max_lines} lines")
        if "\t" in raw:
            raise StrictYAMLError(f"tabs are not allowed at line {number}")
        stripped = _strip_comment(raw).rstrip()
        if not stripped.strip():
            continue
        if stripped.strip() in {"---", "..."}:
            raise StrictYAMLError(f"multi-document YAML is not allowed at line {number}")
        indent = len(stripped) - len(stripped.lstrip(" "))
        text_part = stripped[indent:]
        if text_part.startswith(("!", "&", "*")) or "<<" in text_part:
            raise StrictYAMLError(f"tags, anchors, aliases, and merge keys are not allowed at line {number}")
        prepared.append(_Line(number=number, indent=indent, text=text_part))
    return prepared


def _strip_comment(raw: str) -> str:
    quote = ""
    escaped = False
    for index, char in enumerate(raw):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            continue
        if char == "#" and not quote:
            if index == 0 or raw[index - 1].isspace():
                return raw[:index]
    if quote:
        raise StrictYAMLError("unterminated quoted scalar")
    return raw


def _parse_block(
    lines: list[_Line],
    index: int,
    indent: int,
    *,
    max_nesting: int | None,
    depth: int,
) -> tuple[Any, int]:
    if max_nesting is not None and depth > max_nesting:
        raise StrictYAMLError(f"policy nesting exceeds {max_nesting} levels")
    if lines[index].indent != indent:
        line = lines[index]
        raise StrictYAMLError(f"unexpected indentation at line {line.number}")
    if lines[index].text.startswith("- "):
        return _parse_list(lines, index, indent, max_nesting=max_nesting, depth=depth)
    return _parse_map(lines, index, indent, max_nesting=max_nesting, depth=depth)


def _parse_list(
    lines: list[_Line],
    index: int,
    indent: int,
    *,
    max_nesting: int | None,
    depth: int,
) -> tuple[list[Any], int]:
    result: list[Any] = []
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise StrictYAMLError(f"unexpected list indentation at line {line.number}")
        if not line.text.startswith("- "):
            break

        rest = line.text[2:].strip()
        index += 1
        if not rest:
            if index >= len(lines) or lines[index].indent <= indent:
                result.append(None)
                continue
            item, index = _parse_block(lines, index, lines[index].indent, max_nesting=max_nesting, depth=depth + 1)
            result.append(item)
            continue

        key_value = _split_key_value(rest)
        if key_value is None:
            result.append(_parse_scalar(rest, line.number))
            continue

        key, raw_value = key_value
        item: dict[str, Any] = {}
        if raw_value == "":
            if index >= len(lines) or lines[index].indent <= indent:
                item[key] = None
            else:
                child, index = _parse_block(lines, index, lines[index].indent, max_nesting=max_nesting, depth=depth + 1)
                item[key] = child
        else:
            item[key] = _parse_scalar(raw_value, line.number)

        if index < len(lines) and lines[index].indent > indent:
            child, index = _parse_block(lines, index, lines[index].indent, max_nesting=max_nesting, depth=depth + 1)
            if not isinstance(child, dict):
                raise StrictYAMLError(f"expected mapping continuation at line {lines[index - 1].number}")
            for child_key in child:
                if child_key in item:
                    raise StrictYAMLError(f"duplicate key {child_key!r} near line {line.number}")
            item.update(child)
        result.append(item)
    return result, index


def _parse_map(
    lines: list[_Line],
    index: int,
    indent: int,
    *,
    max_nesting: int | None,
    depth: int,
) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    while index < len(lines):
        line = lines[index]
        if line.indent < indent:
            break
        if line.indent > indent:
            raise StrictYAMLError(f"unexpected mapping indentation at line {line.number}")
        if line.text.startswith("- "):
            break

        key_value = _split_key_value(line.text)
        if key_value is None:
            raise StrictYAMLError(f"expected key/value mapping at line {line.number}")
        key, raw_value = key_value
        if key in result:
            raise StrictYAMLError(f"duplicate key {key!r} at line {line.number}")
        index += 1
        if raw_value == "":
            if index >= len(lines) or lines[index].indent <= indent:
                result[key] = None
            else:
                child, index = _parse_block(lines, index, lines[index].indent, max_nesting=max_nesting, depth=depth + 1)
                result[key] = child
        else:
            result[key] = _parse_scalar(raw_value, line.number)
    return result, index


def _split_key_value(text: str) -> tuple[str, str] | None:
    quote = ""
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if quote == '"' and char == "\\":
            escaped = True
            continue
        if char in {"'", '"'}:
            if not quote:
                quote = char
            elif quote == char:
                quote = ""
            continue
        if char == ":" and not quote:
            key = text[:index].strip()
            if not _KEY_RE.match(key):
                return None
            value = text[index + 1 :].strip()
            return key, value
    return None


def _parse_scalar(value: str, line_number: int) -> Any:
    if value in {"[]", "{}", "|", ">"} or value.startswith(("[", "{")):
        raise StrictYAMLError(f"unsupported YAML scalar at line {line_number}")
    if value.startswith(("!", "&", "*")):
        raise StrictYAMLError(f"tags, anchors, and aliases are not allowed at line {line_number}")
    if value in {"true", "True"}:
        return True
    if value in {"false", "False"}:
        return False
    if value in {"null", "Null", "~"}:
        return None
    if re.fullmatch(r"0|[-]?[1-9][0-9]*", value):
        return int(value)
    if value.startswith('"') or value.startswith("'"):
        return _parse_quoted(value, line_number)
    if any(marker in value for marker in (" !", " &", " *")):
        raise StrictYAMLError(f"tags, anchors, and aliases are not allowed at line {line_number}")
    return value


def _parse_quoted(value: str, line_number: int) -> str:
    quote = value[0]
    if not value.endswith(quote) or len(value) == 1:
        raise StrictYAMLError(f"unterminated quoted scalar at line {line_number}")
    body = value[1:-1]
    if quote == "'":
        return _reject_invalid_unicode_scalars(body.replace("''", "'"), line_number)
    return _decode_double_quoted_yaml(body, line_number)


_DOUBLE_QUOTED_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    '"': '"',
    "/": "/",
    "\\": "\\",
    " ": " ",
    "_": "\xa0",
    "N": "\x85",
    "L": "\u2028",
    "P": "\u2029",
}


def _decode_double_quoted_yaml(body: str, line_number: int) -> str:
    result: list[str] = []
    index = 0
    while index < len(body):
        char = body[index]
        if char != "\\":
            _reject_invalid_unicode_scalar(char, line_number)
            result.append(char)
            index += 1
            continue

        index += 1
        if index >= len(body):
            raise StrictYAMLError(f"invalid escape at line {line_number}")
        escape = body[index]
        index += 1
        if escape in _DOUBLE_QUOTED_ESCAPES:
            result.append(_DOUBLE_QUOTED_ESCAPES[escape])
            continue
        if escape in {"x", "u", "U"}:
            width = {"x": 2, "u": 4, "U": 8}[escape]
            hex_digits = body[index : index + width]
            if len(hex_digits) != width or not re.fullmatch(r"[0-9A-Fa-f]+", hex_digits):
                raise StrictYAMLError(f"invalid escape at line {line_number}")
            codepoint = int(hex_digits, 16)
            try:
                char = chr(codepoint)
            except ValueError as exc:
                raise StrictYAMLError(f"invalid Unicode scalar at line {line_number}") from exc
            _reject_invalid_unicode_scalar(char, line_number)
            result.append(char)
            index += width
            continue
        raise StrictYAMLError(f"invalid escape at line {line_number}")
    return "".join(result)


def _reject_invalid_unicode_scalars(value: str, line_number: int) -> str:
    for char in value:
        _reject_invalid_unicode_scalar(char, line_number)
    return value


def _reject_invalid_unicode_scalar(char: str, line_number: int) -> None:
    codepoint = ord(char)
    if 0xD800 <= codepoint <= 0xDFFF:
        raise StrictYAMLError(f"invalid Unicode scalar at line {line_number}")
