"""Explicit structural preconditions for Cartesian transport classification.

The gate is deliberately separate from :mod:`rcsc.transport_oracle`.  It records
program/declaration admission, expanded-domain well-formedness, and exact repair
membership.  The repair result is *not independent evidence*: it reuses the same
``rcsc.repair.check_repair_membership`` implementation as the production pair and
transport checkers.  This module never invokes the transport footprint, abstract
interpreter, or root-table verifier.
"""
from __future__ import annotations

from typing import Any, Mapping

from .model import context_skeleton, stable_json, validate_program, value_key
from .repair import check_repair_membership, expected_repair


def _failure(component: str, reason: str, detail: Any = None) -> dict[str, Any]:
    return {"component": component, "reason": reason, "detail": detail}


def relation_preconditions(packet: Mapping[str, Any]) -> dict[str, Any]:
    """Check relation-level structural premises without transport factorization."""
    result: dict[str, Any] = {
        "admission_ok": False,
        "declarations_ok": False,
        "context_domains_ok": False,
        "repair_membership_ok": False,
        "preconditions_ok": False,
        "diagnostics": [],
        "repair_check_independent": False,
        "shared_repair_checker": "rcsc.repair.check_repair_membership",
        "uses_transport_footprint": False,
        "uses_context_abstract_interpreter": False,
        "uses_root_table": False,
    }
    diagnostics: list[dict[str, Any]] = result["diagnostics"]
    try:
        if type(packet) is not dict:
            diagnostics.append(_failure("packet", "packet-not-object"))
            return result
        vulnerable = packet["vulnerable"]
        patched = packet["patched"]
        context_domains = packet["context_domains"]
        validate_program(vulnerable)
        validate_program(patched)
        result["admission_ok"] = True
    except (KeyError, ValueError, TypeError, OverflowError) as exc:
        diagnostics.append(_failure("admission", type(exc).__name__, str(exc)))
        return result

    declaration_checks = [
        (
            vulnerable["label"] == "vulnerable" and patched["label"] == "patched",
            "opposite-endpoint-labels",
        ),
        (vulnerable["profile"] == patched["profile"], "profile-equality"),
        (vulnerable["family"] == patched["family"], "family-equality"),
        (
            stable_json(vulnerable["input_domains"]) == stable_json(patched["input_domains"]),
            "input-domain-equality",
        ),
        (
            stable_json(context_skeleton(vulnerable)) == stable_json(context_skeleton(patched)),
            "context-declaration-equality",
        ),
    ]
    failed_declarations = [name for ok, name in declaration_checks if not ok]
    result["declarations_ok"] = not failed_declarations
    if failed_declarations:
        diagnostics.append(
            _failure("declarations", "declaration-mismatch", failed_declarations)
        )

    context_ok = type(context_domains) is dict
    context_details: list[dict[str, Any]] = []
    if not context_ok:
        context_details.append({"reason": "context-domains-not-object"})
    else:
        for name, domain in sorted(context_domains.items()):
            if name not in vulnerable["input_domains"] or name not in patched["input_domains"]:
                context_ok = False
                context_details.append({"name": name, "reason": "undeclared-context-input"})
                continue
            anchor = vulnerable["input_domains"][name]
            if type(anchor) is not list or len(anchor) != 1:
                context_ok = False
                context_details.append({"name": name, "reason": "anchor-not-singleton"})
            if type(domain) is not list or not domain:
                context_ok = False
                context_details.append({"name": name, "reason": "expanded-domain-empty-or-malformed"})
                continue
            if any(type(value) not in (int, bool, str, type(None)) for value in domain):
                context_ok = False
                context_details.append({"name": name, "reason": "expanded-domain-nonscalar"})
            if len({stable_json(value) for value in domain}) != len(domain):
                context_ok = False
                context_details.append({"name": name, "reason": "expanded-domain-duplicate"})
            if type(anchor) is list and len(anchor) == 1 and not any(
                value_key(value) == value_key(anchor[0]) for value in domain
            ):
                context_ok = False
                context_details.append({"name": name, "reason": "anchor-not-in-expanded-domain"})
    result["context_domains_ok"] = context_ok
    if not context_ok:
        diagnostics.append(_failure("context-domains", "invalid-expanded-domain", context_details))

    try:
        declared_repair = expected_repair(vulnerable["family"])
        repair_reason, repair_detail = check_repair_membership(
            vulnerable, patched, declared_repair
        )
        result["repair_membership_ok"] = repair_reason is None
        result["repair_reason"] = repair_reason or "accepted"
        result["repair_detail"] = repair_detail
        if repair_reason is not None:
            diagnostics.append(_failure("exact-repair-membership", repair_reason, repair_detail))
    except (KeyError, ValueError, TypeError, OverflowError) as exc:
        result["repair_reason"] = type(exc).__name__
        result["repair_detail"] = str(exc)
        diagnostics.append(
            _failure("exact-repair-membership", type(exc).__name__, str(exc))
        )

    result["preconditions_ok"] = bool(
        result["admission_ok"]
        and result["declarations_ok"]
        and result["context_domains_ok"]
        and result["repair_membership_ok"]
    )
    return result
