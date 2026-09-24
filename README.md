# Context transport for root-cause-controlled vulnerability benchmarks

This repository checks when a declared vulnerable/patched pair remains the same
security experiment across a Cartesian family of context inputs. It is a finite,
consumer-checked protocol, not a native-language vulnerability detector. The
consumer reconstructs exact repair membership, root dependencies, boundary
stores, and totality/resource bounds. It replays the root input table rather than
the entire context product. The root table is checked, not trusted.

The guarantee has two different axes. Across contexts, each endpoint retains the
same security and abort profile for a fixed root input, with uniform vulnerable
and productive-safe root witnesses. Within each context, the repair preserves
all nonviolating observations of the vulnerable endpoint. Functional outputs
may change across contexts. `TRANSPORT_PROOFS.md` gives the complete contract,
sufficient fragment, proof arguments, reuse rule, counterexamples, and limits.

## Reproduce from this repository alone

Use a POSIX host, Python, and its standard library. No network, model, compiler,
solver, downloaded dependency, or external account is needed for these commands.
Run from this directory, in the displayed order:

```sh
PYTHONDONTWRITEBYTECODE=1 python run_tests.py
PYTHONDONTWRITEBYTECODE=1 python audit_literature.py
PYTHONDONTWRITEBYTECODE=1 timeout 120s python reproduce.py --output results
PYTHONDONTWRITEBYTECODE=1 python check_results.py results
PYTHONDONTWRITEBYTECODE=1 timeout 120s python reproduce_transport.py --output results
PYTHONDONTWRITEBYTECODE=1 python check_transport_results.py results
PYTHONDONTWRITEBYTECODE=1 python verify.py pair examples/pair.json
PYTHONDONTWRITEBYTECODE=1 python verify.py transform examples/transform.json
PYTHONDONTWRITEBYTECODE=1 python verify.py source-pair examples/source_pair.json
PYTHONDONTWRITEBYTECODE=1 python verify.py transport examples/transport.json
PYTHONDONTWRITEBYTECODE=1 python export_paper_data.py --results results --output paper-data
PYTHONDONTWRITEBYTECODE=1 python export_transport_data.py --results results --output paper-data
```

The first command runs all 124 regression tests and records their identifiers
and outcomes without timing-dependent text in `results/test_summary.json`.
The two campaigns use one worker. The base campaign reconstructs the finite
execution substrate. The transport campaign generates its own 36 primary pairs,
76 controls, and 42 scaling points; its compatibility audit reads the three
finite corpora in `results/` produced by the base campaign. A custom transport
output directory does not change that input location. The two result checkers
reconcile 24 base CSV tables and five transport CSV tables, respectively.
Timing fields vary with the host; logical selections and classifications do not.

The JSON command-line verifier accepts packets up to 2 MiB and installs a
15-second POSIX deadline. Exit zero means accepted, one means a checked rejection,
and two means an input/platform/resource failure. No production CLI exposes an
obligation-skipping switch. `audit_transport` is a certificate-free experimental
baseline that still enforces the same frame and semantic obligations; it is not
the production certificate entry point and is not an independent implementation.

## Transport contract and supported fragment

An ordinary pair anchors each candidate context input at one scalar value.
A transport packet supplies an expanded finite domain containing that anchor.
It describes a family of point-instantiated admitted programs, not one oversized
IR domain. The consumer separates a shared prefix and suffix from contiguous
vulnerable/patched roots. It independently reconstructs the read/write sets,
including implicit monitor inputs, rather than accepting claimed effect lists.

The sufficient fragment has at most 24 root instructions, 128 shared context
instructions, 128 root valuations, 32 context variables, and 32 explicit scalar
values per context variable. Roots contain no emissions or returns. Contexts can
assign, calculate, emit, and finally return, but cannot guard, abort, call, execute
security operations, or write public state. Prefix writes and context input names
must be disjoint from the union of root reads and writes. An abstract type,
interval, and allocation analysis checks all declared context values without
enumerating their Cartesian combinations.

Each root table binds both complete root instruction trees, profile, family,
root domains, initial public state, and reconstructed effects. For every root
valuation, the consumer re-executes both roots and probes all root-accessible
locals and every public-store key. Nonviolating boundary stores must match, a
violating row must exist, a normal safe row must exist, and the patched root must
never violate. Root tables may be reused across separately checked wrappers;
there is no trusted verification cache. The execution reduction comes from the
checked decomposition, not the table representation.

All values are type-distinct JSON trees and observations use emission-time
snapshots. Boolean true is not integer one. Suffix analysis starts from the
post-prefix abstract store and overrides only root-probed values; resetting all
input bindings would be unsound. The resource analysis bounds each complete
execution, not merely the isolated root replay. The formal argument is not a
mechanized proof of the Python implementation.

## Main evidence and negative results

| Question | Retained result |
|---|---|
| Primary scope | 36 owned pairs; six monitors and six wrappers |
| Root-table reuse | Six distinct tables across the 36 pairs |
| Root/full execution agreement | 516 root runs versus 8,256 full endpoint runs |
| Independent immutable comparisons | 8,256 comparisons, zero differences |
| Nontrivial functionality | All 36 pairs have observed context-dependent output |
| Controls | 76 rejections with explicitly different meanings |
| Invalid expanded semantic relations | 27, including 22 accepted at the anchor |
| Semantically valid excluded controls | 13, not counted as attack detection |
| False incoming claims over valid factored relations | 30 |
| Missing-anchor domain declarations | Six |
| Measured scaling | Six families at 0, 2, 4, 6, 8, and 10 binary context inputs |
| Measured scaling endpoint executions | 117,390 |
| Symbolic-only scaling | Six twenty-input products; no full Cartesian replay |
| Compatibility, not expanded-context coverage | 268 of 274 base-valid pairs fit the fragment |

The twenty-input points represent 1,048,576 contexts each. The largest represented
endpoint workload is 25,165,824; it is **not an executed workload**. At ten inputs,
full replay uses 1,024 times as many endpoint executions as root replay, but the
checker also pays for admission, table comparison, and abstract analysis. This is
not a claim of the same wall-time speedup over a general symbolic verifier.

A separate moving-witness regression makes both point-instantiated pairs valid
while changing which root input triggers division by zero. It proves that valid
labels at every context are still weaker than a uniform security partition.
The 13 valid exclusions include identity assignments, true guards, and one
amount overwrite that is harmless over its declared finite domain. Rejection by
a sufficient frame or abstract bound is not itself a semantic counterexample.

`transport_packets.json` and `transport_control_packets.json` retain exact inputs;
`transport_oracle.csv` records exhaustive primary evaluations;
`transport_counterexamples.json` retains off-anchor failures;
`transport_functional_variation.json` retains observable-variation witnesses.
The production checker does not import the generator. The Cartesian oracle does
not use the transport footprint, probe, or abstract-analysis implementation.
It does share the declared monitor semantics; no independent model adequacy claim
is made. Certificate-free factored agreement is explicitly not counted as an
independent soundness check.

## Supporting finite execution evidence

The retained substrate has 556 pairs: 258 constructors, ten public-description
predicate abstractions, and 288 exact observation-grammar pairs. The base relation
accepts 274 and rejects 282. Independent immutable-IR comparisons total 42,004
with no mismatch; the typed boundary matrix has 2,609 cases, including 1,370
expected dynamic errors. Its three paths agree across 7,827 evaluations. The exact
observer oracle has 9,216 matching comparisons; deliberately faulty aliasing,
untyped-equality, and combined observers falsely accept 16, 20, and 52 cases.

The optional project-defined source capsule covers 60 pairs and 2,580 source/IR
comparisons with no mismatch; all 55 bridge controls reject. This is a one-to-one
textual syntax, not C, C++, Solidity, or EVM. Other retained checks include 2,236
named transformations, 46 membership controls, 72 pair controls, 36 certificate-
only controls, eleven mutants, and four nonvacuity/repair boundary cases. Detailed
raw data remain available rather than being promoted to separate contributions.

The pair-conditioned repair quotient is only an auxiliary balance diagnostic.
It requires both endpoints and a validated repair derivation; its one-half
classification result does not establish raw-endpoint label blindness or context
transport. Fourteen-feature subset minimization is similarly limited to its
explicit feature universe, not a general causal diagnosis.

## Bibliography and source records

The manuscript uses 62 scholarly records: 61 recorded peer-reviewed publications
and one explicitly identified preprint. There are no ordinary websites or EIP
records in its research bibliography. The inventory, actual citations, BibTeX,
72-work comparison matrix, and resource ledger are checked for closure. The
inventory records verification dates and bases; the reproduction audit is offline
and performs zero live publisher queries. It does not certify interpretations by
counting entries. Publisher metadata for CodeXGLUE use the dedicated proceedings
volume 1, with no unsupported global page range. A regression guards that fact.

The 24 structural-reading and 48 claim-verification statuses in the matrix are
recorded reading depths, not 72 newly repeated full-paper readings. Full copies
of scholarly works are not redistributed. Stable primary identifiers and
comparison roles make the bibliography separately inspectable.

The standalone `manuscript-records/` snapshot makes citation closure independent
of the paper directory. In the complete project, the same audit can be applied
to actual sources by supplying `--tex ../paper/main.tex --bib
../paper/references.bib`. These optional arguments do not enable network access.

## Map and boundaries

`TRANSPORT_PROOFS.md` defines the principal result; `SPECIFICATION.md` and
`PROOFS.md` define its finite execution and repair substrate. `rcsc/transport.py`
is the consumer, `rcsc/transport_producer.py` the untrusted table builder, and
`rcsc/transport_experiment.py` the bounded experiment and Cartesian oracle.
`tests/`, `examples/`, `results/`, and `paper-data/` hold executable checks, packets,
raw evidence, and data exports. `claim_evidence_ledger.csv` maps the current
manuscript's claims to exact proof, code, test, and result paths. Source rights
and description provenance remain in `external_resources.csv`,
`external_inputs/`, and `THIRD_PARTY_NOTICES.md`.

The trusted boundary includes admission, the fixed monitor semantics, repair
membership, effect extraction, observation representation, abstract bounds, and
the host runtime. The fragment is sufficient and incomplete. There is no native
front end, representative real-vulnerability sample, model experiment, deployment
study, whole-implementation mechanization, or universal shortcut-removal result.
All executions use owned benign finite models. No exploit reproduction or
third-party interaction is part of the artifact.
