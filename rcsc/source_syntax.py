"""Concrete source-capsule syntax for the bounded RCSC profiles.

The syntax is intentionally small and deterministic.  It is not C, Solidity, or
an attempt to accept arbitrary native source.  It gives the finite artifact a
reviewable textual source layer whose declarations and statements translate
one-for-one into the admitted IR.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Iterable

MAX_SOURCE_BYTES = 256 * 1024
MAX_SOURCE_LINES = 4096
MAX_SOURCE_LINE = 8192
MAX_SOURCE_INTEGER_BITS = 256


class SourceSyntaxError(ValueError):
    """The source capsule is outside the frozen textual grammar."""


@dataclass(frozen=True)
class Expr:
    kind: str
    value: Any = None
    left: "Expr | None" = None
    right: "Expr | None" = None


@dataclass(frozen=True)
class Statement:
    role: str
    kind: str
    args: tuple[Any, ...]


@dataclass(frozen=True)
class SourceProgram:
    program_id: str
    profile: str
    family: str
    label: str
    parameters: dict[str, Any]
    input_domains: dict[str, list[Any]]
    context: dict[str, Any]
    initial_public_state: dict[str, Any]
    public_projection: tuple[str, ...]
    statements: tuple[Statement, ...]


_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_PROGRAM_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_RESERVED_IDENTIFIERS = {"true", "false", "null"}
_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<INT>0|[1-9][0-9]*)|"
    r"(?P<STRING>\"(?:\\.|[^\"\\])*\")|"
    r"(?P<OP>\&\&|\|\||==|!=|<=|>=|[()!,+\-*.<>=])|"
    r"(?P<IDENT>[A-Za-z_][A-Za-z0-9_]*)"
    r")"
)


def _bounded_int(text: str) -> int:
    value = int(text)
    if value.bit_length() > MAX_SOURCE_INTEGER_BITS:
        raise SourceSyntaxError("integer literal exceeds the source bound")
    return value


def _duplicate_object(items: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in items:
        if key in out:
            raise SourceSyntaxError(f"duplicate JSON object key {key!r}")
        out[key] = value
    return out


def _reject_noninteger(_: str) -> None:
    raise SourceSyntaxError("floating-point and nonfinite literals are outside the source fragment")


def _json_literal(text: str, line: int) -> Any:
    try:
        return json.loads(
            text,
            object_pairs_hook=_duplicate_object,
            parse_int=_bounded_int,
            parse_float=_reject_noninteger,
            parse_constant=_reject_noninteger,
        )
    except (json.JSONDecodeError, SourceSyntaxError, ValueError) as exc:
        raise SourceSyntaxError(f"line {line}: invalid JSON literal: {exc}") from exc


def _name(value: str, line: int, what: str = "identifier") -> str:
    if not _IDENTIFIER.fullmatch(value) or value in _RESERVED_IDENTIFIERS:
        raise SourceSyntaxError(f"line {line}: invalid {what} {value!r}")
    return value


class _ExprParser:
    def __init__(self, text: str, line: int):
        self.text = text
        self.line = line
        self.tokens: list[tuple[str, str]] = []
        pos = 0
        while pos < len(text):
            match = _TOKEN_RE.match(text, pos)
            if not match:
                raise SourceSyntaxError(f"line {line}: invalid expression near {text[pos:pos+24]!r}")
            kind = match.lastgroup
            assert kind is not None
            self.tokens.append((kind, match.group(kind)))
            pos = match.end()
        self.index = 0

    def peek(self, value: str | None = None) -> bool:
        if self.index >= len(self.tokens):
            return False
        return value is None or self.tokens[self.index][1] == value

    def take(self, value: str | None = None) -> tuple[str, str]:
        if self.index >= len(self.tokens):
            expected = value if value is not None else "token"
            raise SourceSyntaxError(f"line {self.line}: expected {expected}, found end of expression")
        token = self.tokens[self.index]
        if value is not None and token[1] != value:
            raise SourceSyntaxError(
                f"line {self.line}: expected {value!r}, found {token[1]!r}"
            )
        self.index += 1
        return token

    def parse(self) -> Expr:
        if not self.tokens:
            raise SourceSyntaxError(f"line {self.line}: empty expression")
        result = self.parse_or()
        if self.index != len(self.tokens):
            raise SourceSyntaxError(
                f"line {self.line}: unexpected token {self.tokens[self.index][1]!r}"
            )
        return result

    def parse_or(self) -> Expr:
        left = self.parse_and()
        while self.peek("||"):
            self.take("||")
            left = Expr("binary", "or", left, self.parse_and())
        return left

    def parse_and(self) -> Expr:
        left = self.parse_equality()
        while self.peek("&&"):
            self.take("&&")
            left = Expr("binary", "and", left, self.parse_equality())
        return left

    def parse_equality(self) -> Expr:
        left = self.parse_relation()
        while self.peek("==") or self.peek("!="):
            op = self.take()[1]
            left = Expr("binary", "eq" if op == "==" else "ne", left, self.parse_relation())
        return left

    def parse_relation(self) -> Expr:
        left = self.parse_additive()
        mapping = {"<": "lt", "<=": "le", ">": "gt", ">=": "ge"}
        while any(self.peek(op) for op in mapping):
            op = self.take()[1]
            left = Expr("binary", mapping[op], left, self.parse_additive())
        return left

    def parse_additive(self) -> Expr:
        left = self.parse_multiplicative()
        while self.peek("+") or self.peek("-"):
            op = self.take()[1]
            left = Expr("binary", "add" if op == "+" else "sub", left, self.parse_multiplicative())
        return left

    def parse_multiplicative(self) -> Expr:
        left = self.parse_unary()
        while self.peek("*"):
            self.take("*")
            left = Expr("binary", "mul", left, self.parse_unary())
        return left

    def parse_unary(self) -> Expr:
        if self.peek("!"):
            self.take("!")
            return Expr("unary", "not", self.parse_unary(), None)
        if self.peek("-"):
            self.take("-")
            return Expr("unary", "neg", self.parse_unary(), None)
        return self.parse_primary()

    def parse_primary(self) -> Expr:
        kind, value = self.take()
        if kind == "INT":
            return Expr("literal", _bounded_int(value))
        if kind == "STRING":
            return Expr("literal", _json_literal(value, self.line))
        if kind == "IDENT":
            if value == "true":
                return Expr("literal", True)
            if value == "false":
                return Expr("literal", False)
            if value == "null":
                return Expr("literal", None)
            if value == "state" and self.peek("."):
                self.take(".")
                name_kind, name = self.take()
                if name_kind != "IDENT":
                    raise SourceSyntaxError(f"line {self.line}: state member must be an identifier")
                return Expr("state", _name(name, self.line, "state key"))
            return Expr("variable", _name(value, self.line))
        if value == "(":
            nested = self.parse_or()
            self.take(")")
            return nested
        raise SourceSyntaxError(f"line {self.line}: unexpected token {value!r}")


def parse_expr(text: str, line: int) -> Expr:
    return _ExprParser(text.strip(), line).parse()


def _split_args(text: str, line: int) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    in_string = False
    escaped = False
    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise SourceSyntaxError(f"line {line}: unbalanced parentheses")
        elif char == "," and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
    if in_string or depth != 0:
        raise SourceSyntaxError(f"line {line}: unbalanced string or parentheses")
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    elif text.strip():
        raise SourceSyntaxError(f"line {line}: empty final argument")
    return parts


def _call(body: str, name: str, line: int) -> list[str] | None:
    prefix = name + "("
    if not body.startswith(prefix) or not body.endswith(")"):
        return None
    return _split_args(body[len(prefix):-1], line)


def _parse_statement(role: str, body: str, line: int) -> Statement:
    if role not in {"context", "root"}:
        raise SourceSyntaxError(f"line {line}: invalid instruction role")

    if body == "nop":
        return Statement(role, "nop", ())
    if body.startswith("nop "):
        tag = _json_literal(body[4:].strip(), line)
        if type(tag) is not str:
            raise SourceSyntaxError(f"line {line}: nop tag must be a JSON string")
        return Statement(role, "nop", (tag,))

    match = re.fullmatch(r"let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", body)
    if match:
        dst, rhs = match.groups()
        dst = _name(dst, line, "assignment destination")
        args = _call(rhs.strip(), "div", line)
        if args is not None:
            if len(args) != 2:
                raise SourceSyntaxError(f"line {line}: div expects two arguments")
            return Statement(role, "divide", (dst, parse_expr(args[0], line), parse_expr(args[1], line)))
        args = _call(rhs.strip(), "add_fixed", line)
        if args is not None:
            if len(args) != 4:
                raise SourceSyntaxError(f"line {line}: add_fixed expects four arguments")
            if not re.fullmatch(r"[0-9]+", args[2]):
                raise SourceSyntaxError(f"line {line}: add_fixed width must be a positive integer literal")
            width = _bounded_int(args[2])
            if width < 1:
                raise SourceSyntaxError(f"line {line}: add_fixed width must be positive")
            if args[3] not in {"signed", "unsigned"}:
                raise SourceSyntaxError(f"line {line}: add_fixed mode must be signed or unsigned")
            return Statement(
                role,
                "add_fixed",
                (dst, parse_expr(args[0], line), parse_expr(args[1], line), width, args[3] == "signed"),
            )
        return Statement(role, "assign", (dst, parse_expr(rhs, line)))

    args = _call(body, "require", line)
    if args is not None:
        if len(args) != 1:
            raise SourceSyntaxError(f"line {line}: require expects one argument")
        return Statement(role, "guard", (parse_expr(args[0], line),))

    args = _call(body, "abort_if", line)
    if args is not None:
        if len(args) != 1:
            raise SourceSyntaxError(f"line {line}: abort_if expects one argument")
        return Statement(role, "branch_abort", (parse_expr(args[0], line),))

    for name, count, kind in (
        ("protected_store", 3, "protected_store"),
        ("external_call", 3, "external_call"),
        ("update_balance", 3, "update_balance"),
        ("commit_after_call", 2, "commit_after_call"),
    ):
        args = _call(body, name, line)
        if args is None:
            continue
        if len(args) != count:
            raise SourceSyntaxError(f"line {line}: {name} expects {count} arguments")
        if kind == "protected_store":
            return Statement(role, kind, (_name(args[0], line), _name(args[1], line), parse_expr(args[2], line)))
        if kind in {"external_call", "update_balance"}:
            return Statement(role, kind, (_name(args[0], line), _name(args[1], line), parse_expr(args[2], line)))
        return Statement(role, kind, (_name(args[0], line), parse_expr(args[1], line)))

    args = _call(body, "low_call", line)
    if args is not None:
        if len(args) != 1:
            raise SourceSyntaxError(f"line {line}: low_call expects one argument")
        return Statement(role, "low_call", (_name(args[0], line),))

    args = _call(body, "check_call", line)
    if args is not None:
        if args:
            raise SourceSyntaxError(f"line {line}: check_call expects no arguments")
        return Statement(role, "check_call", ())

    args = _call(body, "emit", line)
    if args is not None:
        if len(args) not in {1, 2}:
            raise SourceSyntaxError(f"line {line}: emit expects one or two arguments")
        event = _json_literal(args[0], line)
        if type(event) is not str or not event:
            raise SourceSyntaxError(f"line {line}: emit name must be a nonempty JSON string")
        return Statement(role, "emit", (event,) if len(args) == 1 else (event, parse_expr(args[1], line)))

    if body == "return":
        return Statement(role, "return", ())
    if body.startswith("return "):
        return Statement(role, "return", (parse_expr(body[7:].strip(), line),))

    match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*)\s*\[(.*)\]\s*=\s*(.*)", body)
    if match:
        buffer_name, index, value = match.groups()
        return Statement(role, "buf_write", (_name(buffer_name, line), parse_expr(index, line), parse_expr(value, line)))

    raise SourceSyntaxError(f"line {line}: unsupported statement {body!r}")


def parse_source(text: str) -> SourceProgram:
    if type(text) is not str:
        raise SourceSyntaxError("source capsule must be text")
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SourceSyntaxError("source capsule is not valid UTF-8 text") from exc
    if len(encoded) > MAX_SOURCE_BYTES:
        raise SourceSyntaxError("source capsule exceeds the byte bound")
    if "\x00" in text:
        raise SourceSyntaxError("source capsule contains a NUL byte")
    raw_lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    if len(raw_lines) > MAX_SOURCE_LINES:
        raise SourceSyntaxError("source capsule exceeds the line bound")
    if any(len(line.encode("utf-8")) > MAX_SOURCE_LINE for line in raw_lines):
        raise SourceSyntaxError("source capsule contains an overlong line")

    lines = [(index + 1, line.strip()) for index, line in enumerate(raw_lines) if line.strip()]
    if not lines or lines[0][1] != "rcsc-source 1;":
        raise SourceSyntaxError("first nonempty line must be 'rcsc-source 1;'")

    scalar: dict[str, str] = {}
    parameters: dict[str, Any] = {}
    inputs: dict[str, list[Any]] = {}
    context: dict[str, Any] = {}
    state: dict[str, Any] = {}
    projection: list[str] = []
    statements: list[Statement] = []
    statements_started = False

    def set_scalar(key: str, value: str, line: int) -> None:
        if key in scalar:
            raise SourceSyntaxError(f"line {line}: duplicate {key} directive")
        scalar[key] = value

    def set_mapping(mapping: dict[str, Any], key: str, value: Any, line: int, what: str) -> None:
        if key in mapping:
            raise SourceSyntaxError(f"line {line}: duplicate {what} {key!r}")
        mapping[key] = value

    for line_number, line in lines[1:]:
        instruction = re.fullmatch(r"(context|root)\s*:\s*(.*);", line)
        if instruction:
            statements_started = True
            statements.append(_parse_statement(instruction.group(1), instruction.group(2).strip(), line_number))
            continue
        if statements_started:
            raise SourceSyntaxError(f"line {line_number}: declarations must precede statements")

        match = re.fullmatch(r"program\s+([^;\s]+)\s*;", line)
        if match:
            value = match.group(1)
            if not _PROGRAM_ID.fullmatch(value):
                raise SourceSyntaxError(f"line {line_number}: invalid program id {value!r}")
            set_scalar("program_id", value, line_number)
            continue
        match = re.fullmatch(r"(profile|family|label)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", line)
        if match:
            set_scalar(match.group(1), match.group(2), line_number)
            continue
        match = re.fullmatch(r"(parameter|input|context|state)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*);", line)
        if match:
            kind, name, literal = match.groups()
            name = _name(name, line_number, f"{kind} name")
            value = _json_literal(literal, line_number)
            target = {"parameter": parameters, "input": inputs, "context": context, "state": state}[kind]
            if kind == "input" and (type(value) is not list or not value):
                raise SourceSyntaxError(f"line {line_number}: input domain must be a nonempty JSON array")
            set_mapping(target, name, value, line_number, kind)
            continue
        match = re.fullmatch(r"project\s+([A-Za-z_][A-Za-z0-9_]*)\s*;", line)
        if match:
            name = _name(match.group(1), line_number, "projection name")
            if name in projection:
                raise SourceSyntaxError(f"line {line_number}: duplicate projection {name!r}")
            projection.append(name)
            continue
        raise SourceSyntaxError(f"line {line_number}: unsupported declaration {line!r}")

    required = {"program_id", "profile", "family", "label"}
    missing = sorted(required.difference(scalar))
    if missing:
        raise SourceSyntaxError(f"missing required source directives: {missing}")
    if not inputs:
        raise SourceSyntaxError("source capsule must declare at least one input")
    if not state:
        raise SourceSyntaxError("source capsule must declare public state")
    if not projection:
        raise SourceSyntaxError("source capsule must declare a public projection")
    if not statements:
        raise SourceSyntaxError("source capsule must contain statements")

    return SourceProgram(
        program_id=scalar["program_id"],
        profile=scalar["profile"],
        family=scalar["family"],
        label=scalar["label"],
        parameters=parameters,
        input_domains=inputs,
        context=context,
        initial_public_state=state,
        public_projection=tuple(projection),
        statements=tuple(statements),
    )
