"""Finite program schemas and shared data shapes for RCSC."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from itertools import product
from typing import Any, Dict, Iterator, Mapping, Sequence, Tuple
import copy
import json

JSON = Dict[str, Any]
FAMILIES = {
    "c": ("bounds_write", "divide_zero", "fixed_overflow"),
    "solidity": ("access_control", "reentrancy", "unchecked_call"),
}
VIOLATION_FOR_FAMILY = {
    "bounds_write": "OOB_WRITE",
    "divide_zero": "DIVIDE_BY_ZERO",
    "fixed_overflow": "INTEGER_OVERFLOW",
    "access_control": "UNAUTHORIZED_WRITE",
    "reentrancy": "REENTRANT_WITHDRAWAL",
    "unchecked_call": "UNCHECKED_CALL_FAILURE",
}
EXPRESSION_OPS = {
    "add", "sub", "mul", "eq", "ne", "lt", "le", "gt", "ge", "and", "or"
}
INSTRUCTION_FIELDS = {
    "nop": ({"op", "role"}, {"tag"}),
    "assign": ({"op", "role", "dst", "expr"}, set()),
    "guard": ({"op", "role", "pred"}, set()),
    "branch_abort": ({"op", "role", "pred"}, set()),
    "buf_write": ({"op", "role", "buffer", "index", "value"}, set()),
    "divide": ({"op", "role", "dst", "numerator", "denominator"}, set()),
    "add_fixed": ({"op", "role", "dst", "left", "right", "width", "signed"}, set()),
    "protected_store": ({"op", "role", "owner_key", "key", "value"}, set()),
    "external_call": ({"op", "role", "account_var", "balances_key", "amount"}, set()),
    "update_balance": ({"op", "role", "account_var", "balances_key", "set"}, set()),
    "low_call": ({"op", "role", "success_var"}, set()),
    "check_call": ({"op", "role"}, set()),
    "commit_after_call": ({"op", "role", "key", "value"}, set()),
    "emit": ({"op", "role", "name"}, {"value"}),
    "return": ({"op", "role"}, {"value"}),
}


MAX_PROGRAM_NODES = 50000
MAX_JSON_DEPTH = 40
MAX_TEXT_LENGTH = 4096
MAX_LITERAL_BITS = 256
MAX_VALUE_BITS = 4096
MAX_VALUE_NODES = 8192
MAX_INSTRUCTIONS = 1500
MAX_VARIABLES = 128
MAX_INPUT_VALUATIONS = 4096
MAX_REPLAY_WORK = 500000
MAX_FIXED_WIDTH = 256
MAX_ALLOCATION_NODES = 500000
MAX_TOTAL_TEXT = 1000000


class EvaluationLimit(ValueError):
    """The declared finite evaluator's value budget was exceeded."""


def validate_json_tree(value: Any, *, runtime: bool = False) -> int:
    """Admit only bounded JSON trees, without traversing arbitrary Python objects.

    An iterative preflight precedes recursive schema/semantic processing. Cycles
    are rejected. Shared acyclic subtrees are counted at each occurrence, as they
    would be in a JSON serialization. Runtime values have a separate bound.
    """
    stack = [(value, 0, False)]
    active: set[int] = set()
    nodes = 0
    text = 0
    limit = MAX_VALUE_NODES if runtime else MAX_PROGRAM_NODES
    bits = MAX_VALUE_BITS if runtime else MAX_LITERAL_BITS
    error = EvaluationLimit if runtime else SchemaError
    while stack:
        item, depth, leaving = stack.pop()
        if leaving:
            active.remove(id(item))
            continue
        nodes += 1
        if nodes > limit or depth > MAX_JSON_DEPTH:
            raise error("JSON tree size or depth exceeds the finite admission bound")
        typ = type(item)
        if typ in (dict, list):
            if len(item) > limit:
                raise error("JSON collection exceeds the finite admission bound")
            identity = id(item)
            if identity in active:
                raise error("JSON values must be acyclic")
            active.add(identity)
            stack.append((item, depth, True))
            if typ is dict:
                if any(type(k) is not str or len(k) > MAX_TEXT_LENGTH for k in item):
                    raise error("JSON object keys must be bounded strings")
                text += sum(len(k) for k in item)
                if text > MAX_TOTAL_TEXT:
                    raise error("total JSON text exceeds the finite admission bound")
                stack.extend((x, depth + 1, False) for x in reversed(list(item.values())))
            else:
                stack.extend((x, depth + 1, False) for x in reversed(item))
        elif typ is int:
            if item.bit_length() > bits:
                raise error("integer exceeds the finite value bound")
        elif typ is str:
            text += len(item)
            if text > MAX_TOTAL_TEXT:
                raise error("total JSON text exceeds the finite admission bound")
            if len(item) > MAX_TEXT_LENGTH:
                raise error("string exceeds the finite value bound")
        elif typ not in (bool, type(None)):
            raise error("only null, boolean, integer, string, array and object JSON values are admitted")
    return nodes


def value_key(value: Any) -> Any:
    """Injective, type-tagged value representation for observation equality."""
    typ = type(value)
    if value is None:
        return ("null",)
    if typ is bool:
        return ("bool", value)
    if typ is int:
        return ("int", value)
    if typ is str:
        return ("str", value)
    if typ in (list, tuple):
        return ("array" if typ is list else "tuple", tuple(value_key(x) for x in value))
    if typ is dict:
        return ("object", tuple((k, value_key(value[k])) for k in sorted(value)))
    raise TypeError("unsupported observation value")


def require_integer(value: Any) -> int:
    if type(value) is not int:
        raise TypeError("an integer operand is required; booleans are not integers")
    if value.bit_length() > MAX_VALUE_BITS:
        raise EvaluationLimit("integer exceeds the finite value bound")
    return value


def bounded_result(value: Any) -> Any:
    validate_json_tree(value, runtime=True)
    return value


class ValueBudget:
    """Finite per-execution allocation accounting, shared as a resource guard.

    Evaluators separately implement value copying. A charge checks the shape and
    counts the entire value before each compound-value copy. Retained events and
    state therefore cannot grow by repeatedly copying a large admitted literal.
    """
    def __init__(self) -> None:
        self.nodes = 0

    def charge(self, value: Any) -> Any:
        count = validate_json_tree(value, runtime=True)
        if self.nodes + count > MAX_ALLOCATION_NODES:
            raise EvaluationLimit("per-execution value allocation bound exceeded")
        self.nodes += count
        return value


class SchemaError(ValueError):
    """A program or input does not satisfy the frozen artifact schema."""


@dataclass(frozen=True)
class RunResult:
    violation: str | None
    aborted: bool
    returned: Any
    events: Tuple[Tuple[str, Any], ...]
    public_state: Tuple[Tuple[str, Any], ...]
    steps: int
    trace: Tuple[str, ...]

    def observation(self) -> Tuple[Any, ...]:
        return value_key((self.aborted, self.returned, self.events, self.public_state))

    def semantic(self) -> Tuple[Any, ...]:
        return (self.violation,) + self.observation()

    def to_json(self) -> JSON:
        return asdict(self)


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def clone_program(program: Mapping[str, Any]) -> JSON:
    return copy.deepcopy(dict(program))


def freeze_value(value: Any) -> Any:
    if isinstance(value, dict):
        return tuple((k, freeze_value(value[k])) for k in sorted(value))
    if isinstance(value, list):
        return tuple(freeze_value(x) for x in value)
    return value


def project_public(public: Mapping[str, Any], names: Sequence[str]) -> Tuple[Tuple[str, Any], ...]:
    return tuple((name, copy.deepcopy(public[name])) for name in names)


def json_size(value: Any) -> int:
    return len(json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True).encode("utf-8"))


def _identifier(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise SchemaError(f"{where} must be a nonempty string")
    return value


def _validate_expr(expr: Any, variables: set[str], public_names: set[str], where: str) -> None:
    if not isinstance(expr, dict):
        return
    keys = set(expr)
    if keys == {"const"}:
        return
    if keys == {"var"}:
        name = _identifier(expr["var"], f"{where}.var")
        if name not in variables:
            raise SchemaError(f"unknown variable {name!r} in {where}")
        return
    if keys == {"public"}:
        name = _identifier(expr["public"], f"{where}.public")
        if name not in public_names:
            raise SchemaError(f"unknown public key {name!r} in {where}")
        return
    op = expr.get("op")
    if op == "not" and keys == {"op", "arg"}:
        _validate_expr(expr["arg"], variables, public_names, f"{where}.arg")
        return
    if op in EXPRESSION_OPS and keys == {"op", "left", "right"}:
        _validate_expr(expr["left"], variables, public_names, f"{where}.left")
        _validate_expr(expr["right"], variables, public_names, f"{where}.right")
        return
    raise SchemaError(f"malformed expression in {where}")


def _require_public_key(program: Mapping[str, Any], name: Any, where: str, expected_type: type | None = None) -> str:
    key = _identifier(name, where)
    state = program["initial_public_state"]
    if key not in state:
        raise SchemaError(f"unknown public key {key!r} in {where}")
    if expected_type is not None and not isinstance(state[key], expected_type):
        raise SchemaError(f"public key {key!r} has the wrong shape for {where}")
    return key


def _require_variable(name: Any, variables: set[str], where: str) -> str:
    value = _identifier(name, where)
    if value not in variables:
        raise SchemaError(f"unknown variable {value!r} in {where}")
    return value


def validate_program(program: Mapping[str, Any]) -> None:
    if type(program) is not dict:
        raise SchemaError("program must be a plain JSON object")
    node_count = validate_json_tree(program)
    required = {
        "schema", "program_id", "profile", "family", "label", "parameters",
        "input_domains", "context", "initial_public_state", "public_projection",
        "instructions",
    }
    extra = set(program).difference(required)
    missing = required.difference(program)
    if missing:
        raise SchemaError(f"missing program fields: {sorted(missing)}")
    if extra:
        raise SchemaError(f"unexpected program fields: {sorted(extra)}")
    if program["schema"] != "rcsc-program":
        raise SchemaError("unsupported program schema")
    _identifier(program["program_id"], "program_id")
    profile = program["profile"]
    if profile not in FAMILIES or program["family"] not in FAMILIES[profile]:
        raise SchemaError("family/profile mismatch")
    if program["label"] not in {"vulnerable", "patched"}:
        raise SchemaError("bad benchmark label")
    for field in ("parameters", "context", "initial_public_state", "input_domains"):
        if not isinstance(program[field], dict):
            raise SchemaError(f"{field} must be a mapping")

    domains = program["input_domains"]
    if len(domains) > MAX_VARIABLES:
        raise SchemaError("too many input variables")
    if not domains:
        raise SchemaError("input domains must be nonempty")
    for name, values in domains.items():
        _identifier(name, "input domain name")
        if not isinstance(values, list) or not values:
            raise SchemaError(f"domain {name!r} is empty")
        if any(type(value) not in (int, bool, str, type(None)) for value in values):
            raise SchemaError("input domains contain only scalar values")
        encodings = [stable_json(value) for value in values]
        if len(encodings) != len(set(encodings)):
            raise SchemaError(f"domain {name!r} contains duplicate values")

    count = input_count(program)
    if count > MAX_INPUT_VALUATIONS or count * node_count > MAX_REPLAY_WORK:
        raise SchemaError("finite input count or replay-work admission bound exceeded")

    state = program["initial_public_state"]
    public_names = set(state)
    if any(not isinstance(name, str) or not name for name in public_names):
        raise SchemaError("public-state keys must be nonempty strings")

    projection = program["public_projection"]
    if not isinstance(projection, list) or not projection:
        raise SchemaError("public projection must be a nonempty list")
    if len(projection) != len(set(projection)):
        raise SchemaError("public projection contains duplicate keys")
    for name in projection:
        _require_public_key(program, name, "public_projection")

    instructions = program["instructions"]
    if not isinstance(instructions, list) or not instructions:
        raise SchemaError("instructions must be a nonempty list")
    if len(instructions) > MAX_INSTRUCTIONS:
        raise SchemaError("too many instructions")
    variables = set(domains)
    root_count = 0
    for index, inst in enumerate(instructions):
        where = f"instruction {index}"
        if not isinstance(inst, dict):
            raise SchemaError(f"malformed {where}")
        op = inst.get("op")
        if op not in INSTRUCTION_FIELDS:
            raise SchemaError(f"unknown operation {op!r} at {where}")
        exclusive = ({"protected_store", "external_call", "update_balance", "low_call", "check_call", "commit_after_call"}
                     if profile == "c" else {"buf_write", "divide", "add_fixed"})
        if op in exclusive:
            raise SchemaError(f"operation {op!r} is outside the declared profile")
        required_fields, optional_fields = INSTRUCTION_FIELDS[op]
        keys = set(inst)
        missing_fields = required_fields.difference(keys)
        extra_fields = keys.difference(required_fields | optional_fields)
        if missing_fields:
            raise SchemaError(f"missing fields at {where}: {sorted(missing_fields)}")
        if extra_fields:
            raise SchemaError(f"unexpected fields at {where}: {sorted(extra_fields)}")
        role = inst["role"]
        if role not in {"context", "root"}:
            raise SchemaError(f"bad role at {where}")
        root_count += int(role == "root")

        if op == "assign":
            _validate_expr(inst["expr"], variables, public_names, f"{where}.expr")
            variables.add(_identifier(inst["dst"], f"{where}.dst"))
        elif op in {"guard", "branch_abort"}:
            _validate_expr(inst["pred"], variables, public_names, f"{where}.pred")
        elif op == "buf_write":
            _require_public_key(program, inst["buffer"], f"{where}.buffer", list)
            _validate_expr(inst["index"], variables, public_names, f"{where}.index")
            _validate_expr(inst["value"], variables, public_names, f"{where}.value")
        elif op == "divide":
            _validate_expr(inst["numerator"], variables, public_names, f"{where}.numerator")
            _validate_expr(inst["denominator"], variables, public_names, f"{where}.denominator")
            variables.add(_identifier(inst["dst"], f"{where}.dst"))
        elif op == "add_fixed":
            _validate_expr(inst["left"], variables, public_names, f"{where}.left")
            _validate_expr(inst["right"], variables, public_names, f"{where}.right")
            width = inst["width"]
            if isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= MAX_FIXED_WIDTH:
                raise SchemaError(f"invalid width at {where}")
            if not isinstance(inst["signed"], bool):
                raise SchemaError(f"signed must be boolean at {where}")
            variables.add(_identifier(inst["dst"], f"{where}.dst"))
        elif op == "protected_store":
            _require_variable("sender", variables, f"{where}.sender")
            _require_public_key(program, inst["owner_key"], f"{where}.owner_key")
            _require_public_key(program, inst["key"], f"{where}.key")
            _validate_expr(inst["value"], variables, public_names, f"{where}.value")
        elif op == "external_call":
            _require_variable(inst["account_var"], variables, f"{where}.account_var")
            _require_public_key(program, inst["balances_key"], f"{where}.balances_key", dict)
            _validate_expr(inst["amount"], variables, public_names, f"{where}.amount")
        elif op == "update_balance":
            _require_variable(inst["account_var"], variables, f"{where}.account_var")
            _require_public_key(program, inst["balances_key"], f"{where}.balances_key", dict)
            _validate_expr(inst["set"], variables, public_names, f"{where}.set")
        elif op == "low_call":
            _require_variable(inst["success_var"], variables, f"{where}.success_var")
        elif op == "commit_after_call":
            _require_public_key(program, inst["key"], f"{where}.key")
            _validate_expr(inst["value"], variables, public_names, f"{where}.value")
        elif op == "emit":
            _identifier(inst["name"], f"{where}.name")
            if "value" in inst:
                _validate_expr(inst["value"], variables, public_names, f"{where}.value")
        elif op == "return" and "value" in inst:
            _validate_expr(inst["value"], variables, public_names, f"{where}.value")
    if len(variables) > MAX_VARIABLES:
        raise SchemaError("too many declared variables")
    if root_count == 0:
        raise SchemaError("program contains no root-role instruction")


def input_in_domain(program: Mapping[str, Any], inputs: Any) -> bool:
    """Return whether an input mapping exactly instantiates the declared finite domain."""
    if not isinstance(inputs, Mapping):
        return False
    domains = program["input_domains"]
    if set(inputs) != set(domains):
        return False
    for name, value in inputs.items():
        encoded = stable_json(value)
        if not any(encoded == stable_json(candidate) for candidate in domains[name]):
            return False
    return True


def validate_input(program: Mapping[str, Any], inputs: Any) -> None:
    if not input_in_domain(program, inputs):
        raise SchemaError("input is not an exact member of the declared finite domain")


def enumerate_inputs(program: Mapping[str, Any]) -> Iterator[JSON]:
    validate_program(program)
    names = sorted(program["input_domains"])
    domains = [program["input_domains"][name] for name in names]
    for values in product(*domains):
        yield dict(zip(names, values))


def input_count(program: Mapping[str, Any]) -> int:
    count = 1
    for domain in program["input_domains"].values():
        count *= len(domain)
    return count


def context_skeleton(program: Mapping[str, Any]) -> JSON:
    return {
        "profile": program["profile"],
        "family": program["family"],
        "parameters": program["parameters"],
        "input_domains": program["input_domains"],
        "context": program["context"],
        "initial_public_state": program["initial_public_state"],
        "public_projection": program["public_projection"],
        "context_instructions": [
            instruction for instruction in program["instructions"]
            if instruction.get("role", "context") == "context"
        ],
    }


def root_trace_keys(program: Mapping[str, Any]) -> Tuple[str, ...]:
    """Return the execution-trace entries for every declared root instruction.

    The interpreters record one ``"<pc>:<op>"`` entry immediately before each
    instruction executes.  Requiring all of these entries on a non-violating,
    non-aborting vulnerable execution rules out a degenerate "safe" partition
    whose members terminate in context before exercising the declared root.
    """
    return tuple(
        f"{index}:{instruction['op']}"
        for index, instruction in enumerate(program["instructions"])
        if instruction.get("role", "context") == "root"
    )


def is_productive_root_safe(program: Mapping[str, Any], result: RunResult) -> bool:
    """Whether a safe execution completes the declared root slice normally."""
    if result.violation is not None or result.aborted:
        return False
    required = root_trace_keys(program)
    if not required:
        return False
    observed = set(result.trace)
    return all(entry in observed for entry in required)
