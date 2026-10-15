# Context transport for finite vulnerability benchmark pairs

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

Use a POSIX host, Python 3.10 or later and its standard library, plus the
GNU coreutils `timeout` command used in the shell instructions. No network, model, compiler,
solver, downloaded dependency, or external account is needed for these commands.
Run from this directory, in the displayed order:

The campaign and export commands regenerate their selected output files. Use a
fresh copy of the artifact to preserve the delivered results and `paper-data/`.
The result checkers and single-packet verifier only read their supplied evidence.

```sh
PYTHONDONTWRITEBYTECODE=1 python run_tests.py --output results/context_assessment/test_summary.json
PYTHONDONTWRITEBYTECODE=1 python audit_literature.py
PYTHONDONTWRITEBYTECODE=1 timeout 120s python reproduce.py --output results
PYTHONDONTWRITEBYTECODE=1 python check_results.py results
PYTHONDONTWRITEBYTECODE=1 timeout 120s python reproduce_transport.py --output results
PYTHONDONTWRITEBYTECODE=1 python check_transport_results.py results
PYTHONDONTWRITEBYTECODE=1 python reproduce_context_assessment.py
PYTHONDONTWRITEBYTECODE=1 python check_context_assessment.py results/context_assessment
PYTHONDONTWRITEBYTECODE=1 python verify.py pair examples/pair.json
PYTHONDONTWRITEBYTECODE=1 python verify.py transform examples/transform.json
PYTHONDONTWRITEBYTECODE=1 python verify.py source-pair examples/source_pair.json
PYTHONDONTWRITEBYTECODE=1 python verify.py transport examples/transport.json
PYTHONDONTWRITEBYTECODE=1 python export_paper_data.py --results results --output paper-data
PYTHONDONTWRITEBYTECODE=1 python export_transport_data.py --results results --output paper-data
```

The first command discovers the regression suite (including the historical 136
tests, six portable suffix-reuse tests, and the separate assessment tests) and records identifiers
and outcomes without timing-dependent text in the separate current
`results/context_assessment/test_summary.json`, preserving historical test records.
The two campaigns use one worker. The base campaign reconstructs the finite
execution substrate. The transport campaign generates its own 36 primary pairs,
76 controls, and 42 scaling points; its compatibility audit reads the three
finite corpora in `results/` produced by the base campaign. A custom transport
output directory does not change that input location. The two result checkers
reconcile 24 base CSV tables and six transport CSV tables, respectively.
Each scaling row retains three raw transport-check times, and the coordinator
recomputes the median. `transport_summary.json` records the CPU model, visible
logical CPU count, OS/release/architecture, Python implementation/version, and
the CPU, wall-clock, and RSS measurement definitions for the retained rerun.
Timing fields vary with the host; logical selections and classifications do not.

The transport result checker binds oracle rows to the actual root/context product,
reconciles per-row reference-comparison counts, replays the two functional-variation
witnesses for each primary pair, and checks control-packet identities and production
outcomes. Binary null operands remain explicit JSON `null` in the typed boundary
matrix; an empty right-operand cell denotes only unary `not`.

The historical transport campaign's RSS measurement and the CLI deadline require
POSIX. The supplementary assessment uses only the standard library and does not
report platform-specific resource or timing measurements; it also runs on Windows.

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

Within one check, identical complete post-prefix/root-exit abstract stores reuse
successful suffix cost bounds. Keys include every local/public name and each
bound's kinds, integer endpoints, and node count; current exact values are still
validated first. Failures are not cached, and every root row is still replayed.
The certificate-free audit uses the same local reuse. The independent Cartesian
oracle is unchanged. This does not alter the retained measurements or claim a
wall-time improvement. The portable gate needs only this artifact:

```sh
PYTHONDONTWRITEBYTECODE=1 python -m unittest tests.test_suffix_reuse
```

## Main evidence and negative results

| Question | Retained result |
|---|---|
| Primary scope | 36 owned pairs; six monitors and six wrappers |
| Root-table reuse | Six distinct tables across the 36 pairs |
| Root/full execution agreement | 516 root runs versus 8,256 full endpoint runs |
| Independent immutable comparisons | 8,256 comparisons, zero differences |
| Oracle-scope mutations | Two: one semantic-only pass rejected by repair membership; one monitor/declaration mismatch |
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
`transport_oracle.csv` records exhaustive primary semantic evaluations;
`transport_oracle_scope_controls.csv` records the trailing-root-no-op and wrong-
family mutations; `transport_counterexamples.json` retains off-anchor failures;
and `transport_functional_variation.json` retains observable-variation witnesses.
The production checker does not import the generator. `rcsc/transport_oracle.py`
does not import the transport footprint, probe, abstract interpreter, root table,
or repair checker. It checks defined execution, declared-monitor consistency,
patch closure, observations, support, and security-profile invariance over the full
small Cartesian product. Declaration/domain premises and exact repair membership
are recorded separately by `transport_contract_gate.py`. The repair gate reuses the
production repair implementation and is therefore not independent validation.
Certificate-free factored agreement is likewise not counted as an independent
soundness check.

## Supplementary held-out assessment

`reproduce_context_assessment.py` writes only `results/context_assessment/` by
default. It does not replace any historical result table or test count. This is
a 144-pair grid: four owned root configurations per existing monitor and six
wrapper functions. Roots 0/1 and wrappers 0..3 form 48 training pairs. Holding out
roots 2/3, wrappers 4/5, or both gives 48, 24, and 24 test pairs. Both labels and
both representations of a pair stay together. `split_manifest.csv.gz` binds the
actual normalized root objects and context code; neither held-out axis overlaps
its training axis. The six monitor mechanisms themselves are not held out.

Each pair has two ternary integers, one Boolean and one three-valued string:
54 reachable valuations, not 54 new fault mechanisms. `functional_domain.json.gz`
retains a productive-safe root and four one-coordinate observation-change
witnesses. All 54 valuations have distinct typed observations at that root.
Cross-input functions and root-result/context-mode comparisons supplement the
direct emissions. The unused-token regression leaves 54 input valuations but
only 18 observable contexts and three effective coordinates.
The separate historical diagnostic finds 16 distinguishable observations and
four effective coordinates in each original four-input wrapper. Those products
are observable, although their independent-emission functions are shallow.

`rcsc/syntax_normalization.py` applies the same endpoint-local no-op removal and
comparison canonicalization to both labels. It preserves guards, status checks,
effect/call order, literal types, event names and true labels. It never erases a
repair or needs the peer endpoint. Step counts/traces are outside its semantic
equivalence claim. All 111,456 raw/normalized semantic comparisons agree. Across
both representations, 222,912 full endpoint runs and immutable-reference
comparisons agree; these are executed cases. The certificate-free factored audit
agrees with transport on all 288 checks and uses the same root replay counts.

Three fixed feature maps see instruction syntax only, without ids, labels,
certificates, pair side, peer code, runtime outcomes or split annotations. Lookup
cells and fallback are fitted only on 96 training endpoints. Constant and
context-only probes score 50%; guard/status/order probes score 100% on every
held-out split, before and after normalization. `models.json.gz`, `features.json.gz`
and `predictions.csv.gz` retain the training and test separation. The fixed syntax
rule also predicts all 72 historical endpoint labels in both representations;
that is a descriptive channel check, not held-out performance. These results
confirm residual repair-catalogue shortcuts rather than claiming their removal.

Two separate anchored-valid division controls retain correct syntax predictions
but fail expanded transport. `relevance_controls.csv` records their full semantic
counterexamples and frame/control rejections in both representations (192 endpoint
executions, separate from the 222,912 primary runs). This separates predicting a
label from validating a context change. `TRANSPORT_PROOFS.md` Section 10 proves
the observable-domain and normalization claims for this bounded assessment.

`check_context_assessment.py` reconstructs the actual split, typed domain,
training-only models, predictions, replay counts and functional witnesses. It
does not treat the feature probes as learned vulnerability detectors or as an
independent proof of transport. No native or third-party code is executed.

## Ordinary syntax comparison and admission regressions

The ordinary comparison keeps the preceding 144-pair split unchanged. It fits
multinomial naive Bayes on generic typed JSON instruction unigrams, with alpha=1,
empirical training priors, training vocabulary only, ignored unknown tokens and
lexical label ties. This is an order-blind bag of the full instruction syntax,
not three manually selected repair bits. Only 96 training endpoints per
representation are fitted; no test tuning is performed. Root/context/both test
counts are 81/96, 43/48 and 43/48 in both representations. The reentry family
remains at half accuracy, and all other errors/confusions are retained. The
constant/context-only probes remain at half and the repair lookup remains perfect.

Reproduce into **fresh** directories; these runners refuse an existing output:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B reproduce_ordinary_syntax.py --output /tmp/ordinary-syntax
PYTHONDONTWRITEBYTECODE=1 python -B reproduce_ordinary_syntax.py --output /tmp/ordinary-syntax --check
PYTHONDONTWRITEBYTECODE=1 python -B reproduce_context_admission.py --output /tmp/context-admission
```

`results/ordinary_syntax/` retains exact source-byte bindings, normalized
root/context objects, tokens, training counts, log scores, every prediction,
family confusion rows and environment. Input packets remain in the unchanged
`results/context_assessment/`; its gzip-byte hashes bind the comparison source.
Feature extraction and prediction are not counted as program executions.
`results/context_validation/` is a separate fresh replay of that fixed grid on
CPython 3.12.14/Windows. Its raw oracle rows retain per-call attempts/completions;
222,912 Cartesian production runs and reference comparisons agree, separately
from the 111,456 raw/normalized comparisons (two production calls each).
The existing checker can check this directory as well:

```sh
PYTHONDONTWRITEBYTECODE=1 python -B check_context_assessment.py results/context_validation
```

Expanded-domain admission now uses the existing bounded source-JSON preflight.
Integer/text values at 256 bits/4,096 characters pass; the next larger values
reject structurally. Boolean/integer membership remains type-exact.
`results/context_admission/` includes exact finite inputs, gate/consumer outputs,
and observed evaluator calls for natural arithmetic errors. Its 56 production
attempts include only 24 successful returns; undefined relations remain false.
The separately labeled second-core-call injection tests accounting only and
must not be presented as a natural semantic workload. Attempted calls, returned
results, completed pair rows and symbolic represented obligations are distinct.
Current regression identifiers/outcomes are retained separately under
`results/context_validation/test_summary.json` (170 passing tests). The historical
campaign, its 136-test summary and supplementary histories are unchanged.

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
is the consumer, `rcsc/transport_producer.py` the untrusted table builder,
`rcsc/transport_oracle.py` the factorization-independent Cartesian semantic path,
`rcsc/transport_contract_gate.py` the explicitly shared structural-premise gate,
and `rcsc/transport_experiment.py` the bounded experiment coordinator.
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

## Manuscript diagrams

The model and protocol schematics are drawn directly in Python as vector PDFs
with embedded STIX fonts. They encode the stated relationships, not measured
performance. To regenerate them with Python 3.9+ and Matplotlib:

```sh
python -B figures/draw_schematics.py --output figures
```
