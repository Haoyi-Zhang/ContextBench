# Finite pair-certificate specification

The principal context-transport contract is specified in `TRANSPORT_PROOFS.md`.
This document supplies its finite execution, exact repair, source-syntax, and
base-certificate layer. Base pair validity quantifies only over the declared
ordinary input domain; it does not authorize a larger context family. Transport
adds separately checked effects, complete root-exit stores, uniform witnesses,
and context totality. The pair-conditioned quotient below is auxiliary only.

For transport evaluation, the full Cartesian oracle is a semantic oracle rather
than an independent implementation of Definition 1. It checks execution
definedness, the declared family monitor, patched closure, typed observations,
uniform security/abort profiles, and vulnerable/productive-safe support over every
root/context point. Program/declaration equality, expanded-domain admission, and
exact repair membership are checked and recorded separately for each replayed
packet. Exact repair membership reuses the production repair routine and is
therefore explicitly non-independent. Neither transport footprints, abstract
context interpretation, nor root-table verification is used to obtain the
Cartesian semantic verdict.


## 1. Values, packets and admission

A program is an exact `rcsc-program` JSON object containing an identifier, profile,
family, label, parameters, finite input domains, contextual metadata, initial
public state, public projection, and an ordered instruction sequence. Every
instruction has role `context` or `root`. The profiles are abstract catalogues,
not C, C++, Solidity, or EVM parsers.

Values are finite typed JSON trees. Null, boolean, integer, string, array, and
object constructors remain distinct; in particular, boolean `true` is not integer
`1`. Object order is irrelevant and array order is significant. Every read,
assignment, initial state, projected state, and event payload is copied by value.
An event denotes its value at emission, not a mutable reference observed later.

Input domains are nonempty lists of scalar typed values. Execution enumerates the
Cartesian product in sorted variable-name order and declared value-list order;
semantic diagnostics re-sort complete valuations by canonical typed encoding.
Structural domain equality also preserves the declared list order.
Packets reject duplicate keys, floating-point/nonfinite literals, and out-of-bound
resources. Current caps include 50,000 source-tree nodes, depth 40, 1,500
instructions, 128 variables, 4,096 input valuations, 256-bit source integers,
4,096-bit runtime integers, and bounded copied-value allocation. A dynamic type,
shape, value-budget, or deadline failure rejects; it cannot produce acceptance.

The command-line verifier reads at most 2 MiB and installs a 15-second POSIX
wall-clock deadline. Library calls do not silently emulate that deadline on an
unsupported platform. The production pair API has no semantic-ablation arguments.

### 1.1 Bounded concrete source capsules

`rcsc-source-1` is a line-oriented concrete syntax for this finite model. A capsule
starts with `rcsc-source 1;`, then declares one program id, profile, family, label,
parameters, nonempty finite input arrays, context values, initial public state, and
one or more projected state names. Declarations precede statements. Each statement
is explicitly marked `context:` or `root:`. The statement catalogue is exactly the
fifteen IR operations in Section 2; expressions contain literals, variables,
projected-state reads, the twelve admitted arithmetic, comparison, equality, and
boolean operations, and unary negation as syntax sugar for subtraction from zero.
Source text is bounded by 256 KiB, 4,096 lines, 8,192 UTF-8 bytes per line, and
256-bit integer literals. `true`, `false`, and `null` are reserved literal tokens
and cannot be declaration identifiers. Duplicate declarations, duplicate JSON
object keys, floating-point values, unsupported syntax, and late declarations
reject.

The compiler is syntax directed: each declaration and statement has exactly one IR
constructor, preserves order and role, and performs ordinary IR admission on the
result. It does not infer omitted types, desugar loops, resolve aliases, or accept
native C, C++, Solidity, or EVM. A source-pair packet supplies both source strings,
the two claimed IR endpoints, a source certificate, and the ordinary pair
certificate. The source certificate binds the pair id, both endpoint ids, profile,
family, and language. Verification reparses and recompiles both strings, requires
exact structural equality with the supplied IR, compares direct source execution
on every declared input with the producer evaluator, consumer evaluator, and
immutable IR reference, and finally applies the strengthened pair relation. A malformed, cyclic, over-deep, or otherwise inadmissible supplied IR endpoint returns a structured `source-ir-admission-error`; a dynamic source or IR execution failure returns a structured `source-execution-error`. Neither can authorize the pair. Thus a source edit, endpoint substitution,
compiler-output substitution, or pair-witness substitution cannot be hidden behind
an otherwise valid IR certificate.

## 2. Operational semantics

For admitted program `Q` and input `i`, deterministic execution returns

`Exec(Q,i) = (violation, abort, return, events, projected state, trace)`.

The first violation, abort, or return stops execution. Falling off the instruction
list returns null. Diagnostic traces and an internal termination flag are not
observations. Expressions use exact integer arithmetic, typed equality, eager
boolean connectives, and explicit truthiness. Division truncates toward zero.

The six monitored root families are:

| Profile | Family | Monitored event | Designated repair |
|---|---|---|---|
| C-like | bounds write | out-of-range indexed write | insert one bound guard immediately before the protected write |
| C-like | divide by zero | denominator is zero | insert one nonzero-denominator guard immediately before division |
| C-like | fixed overflow | mathematical result outside declared width | insert one operand/range-derived guard immediately before fixed-width addition |
| Solidity-like | access control | sender differs from declared owner | insert one sender/owner guard immediately before protected store |
| Solidity-like | reentrancy proxy | callback-capable external interaction precedes balance effect | swap the adjacent root effect before interaction |
| Solidity-like | unchecked-call proxy | failed low-level call reaches an unchecked commit | insert one root status check between call and commit |

These are monitor definitions inside the abstract semantics. They do not diagnose
arbitrary source software. Only the first monitored event is classified.

## 3. Observations and declarations

`Obs(Q,i)` is `(abort, return, ordered event snapshots, projected public state)`.
Every component uses recursive type-tagged equality. The security monitor is
excluded from the nonsecurity observation and compared separately.

`Ctx(Q)` contains profile, family, parameters, ordered input domain, contextual
metadata, initial public state, public projection, and the ordered list of
context-role instructions. Endpoint identifiers, labels, and root instructions
are excluded. Context equality is exact and type-distinct.

## 4. Exact root-repair relation

Let `repair(f)` be the designated edit in the table above. The repair checker
receives only the two supplied instruction sequences, endpoint declarations, and
the declared repair. It never invokes a corpus constructor.

For each guard-repaired family, the patched sequence must equal the vulnerable
sequence with exactly one root guard inserted immediately before the matching root
operation. Deleting the unique guard must reproduce the entire vulnerable
sequence exactly. In addition, the guard predicate must contain a canonical
conjunct tied to the actual protected operands:

- **Bounds.** The predicate contains `index >= 0` and `index < buffer_length`. One
  side may be omitted only when every declared entry value of that same input
  satisfies it and no instruction before the protected write redefines the input.
  The length is read from the declared initial buffer.
- **Division.** The predicate contains `denominator != 0`.
- **Fixed overflow.** The predicate contains at least one exact lower- or
  upper-bound comparison derived from the instruction's two operands, declared
  width, and signedness, such as `x <= U - y` or `x >= L - y`. Reversing comparison
  direction is equivalent, and a constant counterpart may be folded. Exhaustive
  patch closure remains responsible for every other relevant side of the range on
  the declared domain.
- **Access control.** The predicate contains typed equality between the input
  variable `sender` and the protected operation's declared public owner field.

A top-level conjunction may contain additional conjuncts. They do not become part
of the root guarantee: safe-observation equality must independently establish that
they do not suppress or alter any declared safe behavior. Other semantically
equivalent syntax is outside this finite named edit relation unless it contains the
specified conjunct. This is an edit-membership rule, not a claim that the excluded
syntax is insecure.

For the reentrancy proxy, the sequences must differ by exactly one adjacent swap
from `external_call; update_balance` to `update_balance; external_call`, both
root-role instructions. For unchecked call, the patched sequence must equal the
vulnerable sequence with exactly one root `check_call` inserted between the
matching `low_call` and `commit_after_call`.

No other instruction, role, operand, tag, or order may change. Semantic closure is
checked separately; syntactic membership alone is insufficient.

## 5. Strengthened pair relation

For declared vulnerable endpoint `V`, patched endpoint `P`, family monitor `vf`,
and finite domain `D`, `R(V,P)` holds exactly when:

1. both endpoints are admitted, labels are opposite, profile/family/domain agree,
   and `Ctx(V) = Ctx(P)`;
2. the pair is a member of the exact designated root-repair relation;
3. there exists `i_v` in `D` with `Exec(V,i_v).violation = vf`;
4. every violation of `V` in `D` is `vf`;
5. there exists a productive safe `i_s` in `D`: `V` has no violation, does not
   abort, and its execution trace contains every root-role instruction of `V`;
6. `P` has no monitored violation for every input in `D`; and
7. `Obs(V,i) = Obs(P,i)` for every input on which `V` has no violation.

Clauses 3 and 5 make the domain nonvacuous on both sides of the security boundary
and require the benign side to exercise the complete declared root slice rather than
merely aborting in common context before it. Clause 7 still ranges over every
nonviolating vulnerable input, including aborting inputs, so the productive witness
does not weaken preservation. Clause 2 closes both the demonstrated root-syntax
label channel and substitution of an undeclared guard expression for the named root
edit. Clauses 5 and 7 prevent an always-aborting or functionally impaired patch from
passing. Patched behavior on inputs that violate in `V` remains intentionally
underconstrained beyond closure.

The exact pair certificate contains pair id, endpoint ids, declared family,
declared repair, and one violating witness input. Its endpoint ids must be exactly
`<pair-id>-vulnerable` and `<pair-id>-patched`. This naming convention and the
submitted id values belong to certificate claim binding, not to relation `R` after
program admission. Family, repair, membership, domain membership, and witness
behavior are also checked. The witness binds the claim; it does not replace
exhaustive replay and does not authenticate source provenance.

## 6. Nuisance surface and balance

For an accepted exact-repair pair, define `N(V,P)` on the admitted IR endpoints by removing endpoint ids and labels and undoing the single designated repair in `P`. The resulting object contains every shared IR declaration and the complete vulnerable IR instruction sequence. Exact membership guarantees that both endpoints map to this same object.

For any multiset of accepted pairs sampled with one vulnerable and one patched
endpoint per pair, every `N`-cell has equal label multiplicity. Thus the optimal
deterministic classifier measurable only with respect to `N` has empirical
accuracy exactly one half. Any randomized classifier has expected accuracy one
half. This guarantee covers all admitted-IR endpoint information retained in `N`, not just the fourteen diagnostic features. It deliberately excludes the designated repair polarity/root edit, which is the intended label-bearing channel. It also excludes capsule spelling and formatting, certificate fields, filenames, archive layout, and every other packet-level or native-source channel not encoded in `N`.

## 7. Diagnostics

Structural failures return the first type-exact difference under deterministic
key/path traversal. Semantic failures are selected by a fixed clause priority:
execution error, wrong root, residual patched violation, safe-observation mismatch,
missing vulnerable witness, missing safe input, then missing productive safe input.
The last reason means at least one input is nonviolating but every such candidate
aborts or fails to execute the complete root-role sequence. Ties use canonical typed
input encoding, independent of declared domain-list order.

Leakage diagnostics are separate from semantic rejection. For the fixed fourteen
context features, the artifact enumerates subsets by cardinality and lexical order.
It exhausts all 16,383 nonempty subsets for the clean corpus and therefore returns
a globally minimum-cardinality perfect witness within that feature universe. This
is not a globally smallest causal explanation across arbitrary syntax or all
rejection classes.

## 8. Transformations, direct audit, and reference semantics

Four preserving transformations have exact source-target membership relations:
root stutter, root-guard dualization, unread temporary rename, and an independent
initial assignment/no-op swap. Membership is checked directly from source, target,
and derivation before semantic replay. Root-flipping transformations apply exact
repair membership plus every semantic clause of `R`, including a productive safe
root execution, in close-root or open-root direction; a semantic root change alone
is insufficient.

The certificate-free audit independently reconstructs the designated repair,
checks the same finite semantic clauses, and chooses a canonical violating input.
After admission it ignores endpoint identifier values, while the production
certificate layer enforces its pair-id naming and field bindings. The audit shares
schemas, value semantics, and parts of the execution boundary, so it is not an
independent semantic oracle. Its purpose is to distinguish the incoming
certificate from the relation itself.

A separate immutable reference interpreter executes already-admitted programs
without importing project schema, value, evaluator, generator, repair, or checker
modules. It uses immutable type-tagged values and independently implements every
instruction and expression operation admitted by the frozen language. The retained
cross-check covers every operation and expression form across 2,834 programs and
21,002 valuations, comparing both production evaluators with the reference in
42,004 semantic and operational comparisons. This evidence addresses the execution
implementation on that retained set. It is not exhaustive over all programs and
does not independently verify packet parsing, admission, resource enforcement, or
the repair and pair decision procedures.

A frozen semantic-boundary matrix complements that retained corpus. Its expression
stratum applies all twelve operations to an explicit twelve-value set containing
null, Boolean, integer, string, array, and object values: 1,596 cases, of which 945
are expected dynamic errors. Its instruction stratum contains twenty admitted
microprograms covering all fifteen operations and 1,013 valuations, of which 425
raise dynamic execution errors. Producer, consumer, and immutable reference must
agree on definedness in every case and on the exact type-tagged or operational
result whenever defined. The campaign does not equate exception classes or
messages and is exhaustive only for these frozen matrices, not for the admitted
program language.

A second immutable interpreter executes parsed `rcsc-source-1` syntax directly. It
does not import the IR compiler, IR schema/value implementation, either production
evaluator, the IR reference interpreter, corpus generator, repair checker, or pair
checker. For a source result `S` and compiled IR result `I`, the bridge compares the
same typed semantic tuple and, separately, the step count and operation trace. The
retained source campaign covers all source statement and expression operations in
120 programs and 860 valuations. Comparing the source result with both production
IR evaluators and the immutable IR reference yields 2,580 semantic and operational
comparisons. This is evidence for the frozen source language and compiler on the
retained corpus, not a mechanized compiler proof or a statement about a native
language.

The exact 288-pair observation grammar remains a distinct oracle. It computes the
complete order/type partition without either general evaluator or the shared
observation encoder, and therefore provides discriminating evidence for the typed
emission-time equality premise rather than broad execution coverage.
