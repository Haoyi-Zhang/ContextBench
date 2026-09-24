# Proof obligations and theorem ladder

These are proofs for the finite execution and pair/transform substrate. The
principal context-transport soundness theorem, certificate-reuse result,
pointwise-label counterexample, and incompleteness boundary are in
`TRANSPORT_PROOFS.md`. Numbered results in the two documents have separate scopes.
The quotient result here is a balance identity after validated repair erasure,
not the manuscript's central contribution or a raw-endpoint guarantee.


All statements are conditional on admitted, terminating executions in the finite
semantics specified in `SPECIFICATION.md`. They do not prove correctness of a
native-language translation or absence of defects outside the checked Python
implementation.

## Lemma 1: Type-faithful snapshots

For every admitted runtime value, the canonical observation encoder is injective
with respect to the JSON constructor and recursively encoded contents. Every state
read and event emission copies the value tree. Therefore later state updates
cannot alter an earlier event, and equality of encoded observations implies equal
abort bits, return values with types, ordered event names/payloads with
emission-time values, and projected public state with types.

*Argument.* Structural induction on the finite value tree proves injectivity of the
tagged encoding. Copy boundaries create disjoint value trees by occurrence. Tuple
and list equality then preserves observation position and event order. The exact
order/type grammar supplies an executable oracle for the cases most likely to
violate the premises: mutable arrays and boolean/integer equality.

## Lemma 2: Exact repair erasure and root binding

If the repair-membership checker accepts `(V,P,r)`, then undoing the unique edit
specified by `r` in `P` yields the complete instruction sequence of `V` exactly,
including instruction order, operands, roles, and tags. For a guard-repaired
family, the unique guard additionally contains the family's canonical predicate
conjunct bound to the protected operation's actual index and buffer length,
denominator, arithmetic operands/range, or owner field.

*Argument.* Guard and status-check relations search every possible single erasure
and accept only one site whose erased sequence is type-exactly equal to `V`.
Reentrancy accepts only one adjacent root swap whose reconstructed target is
exactly `P`. Length checks rule out extra edits. Guard families then inspect the
protected instruction and require the precise finite predicate pattern from
`SPECIFICATION.md`, allowing only documented comparison reversals, constant
folding, and domain-discharged bounds. A domain-discharged bound is admitted only
when the guarded index is the unchanged entry input up to the protected operation;
otherwise the entry domain says nothing about its later value. The checker uses
supplied sequences and endpoint declarations and does not call the producer
constructor. Extra guard conjuncts remain subject to safe-observation equality.

## Lemma 3: Nonvacuous semantic partition

If the strengthened pair relation accepts, the declared domain contains at least
one vulnerable input and at least one productive safe input for `V`. A productive
safe execution has no violation, does not abort, and executes every root-role
instruction. Every vulnerable execution reports the declared family monitor; `P`
reports no monitor on the entire domain; and observations agree on every input that
is nonviolating in `V`, including aborting ones.

*Argument.* These are separately enumerated acceptance clauses. The witness clause
cannot substitute for productive safe nonvacuity, and patch closure cannot
substitute for observation equality. The empty-safe-domain boundary case is accepted
only by the explicit ablation that removes safe nonvacuity. A second ablation that
counts every nonviolating execution accepts a pair whose only nominally safe input
aborts in common context before the root; the production clause rejects it because
no safe execution completes the root slice.

## Theorem 1: Pair soundness

If the production verifier accepts a packet, then the supplied endpoints satisfy
the strengthened pair relation and the submitted certificate is bound to that
pair, family, designated repair, and a real vulnerable input.

*Proof sketch.* Schema and admission precede all acceptance. Label, family, domain,
and context gates establish clause 1. Lemma 2 establishes clause 2, including the
root predicate identity for inserted guards. Canonically ordered finite replay
establishes clauses 3--7, with Lemma 1 providing the observation equality meaning.
Certificate validation checks exact endpoint ids, family, repair, and domain
membership, and the final witness replay establishes the claimed violation. Every
exception or resource failure takes a rejection path.

## Theorem 2: Conditional completeness

For admitted endpoints satisfying the strengthened relation, suppose the endpoint
identifiers and exact certificate satisfy the production claim-binding schema, the
witness names any vulnerable input, and replay plus witness validation complete
within the applicable dynamic resource and platform-deadline bounds. Then the
production verifier accepts.

*Proof sketch.* Exact declarations, certificate bindings, and repair membership pass
their gates. Finite replay encounters no execution or resource error by assumption.
Each semantic rejection predicate is false by the relation. The named witness is
in-domain and reports the expected monitor. This is conditional completeness for
the bounded implementation contract; it is not a universal latency bound, a claim
about every schema-valid program, or a native-source result.

## Proposition 1: Certificate elimination

For any fixed admitted endpoints, the truth of the strengthened pair relation does
not depend on an incoming certificate or on the particular valid endpoint
identifier values. A certificate-free consumer can enumerate the same domain,
reconstruct the designated repair from the family, decide every relation clause,
and choose the first canonical vulnerable input as a witness.

*Consequence.* The certificate does not compress this implementation's full replay
or strengthen its semantics. It enforces an exact field schema, pair-id/endpoint-id
naming convention, family, repair, and witness claims. The retained direct audit
agrees on all 556 primary pair decisions; thirty-six controls isolate valid
endpoint relations with invalid submitted certificates, including six identifier-
convention substitutions accepted by direct relation audit after admission.

## Theorem 3: Balanced pair-conditioned admitted-IR repair quotient

Let `S` be any multiset of pairs accepted under exact repair membership. Construct the endpoint sample containing one vulnerable and one patched endpoint from each pair. For each accepted pair, let `Q` be the pair-conditioned quotient produced after the verifier uses both endpoints and the validated repair derivation to undo the designated edit, then erases endpoint ids and labels. For every deterministic classifier `h` that receives only `Q`, empirical accuracy on the endpoint sample is exactly one half; the optimum is therefore one half. For every randomized classifier measurable only with respect to `Q`, expected accuracy is one half.

*Proof.* By Lemma 2, both endpoints of each pair have the same normalized surface.
For any surface cell, every contributing pair adds one vulnerable and one patched
endpoint. Hence label counts in every cell are equal. A deterministic classifier
chooses one label per cell and is correct on exactly half of that cell; summing over
cells gives one half. A randomized classifier's expected correct probability in a
balanced cell is `(p + (1-p))/2 = 1/2`, and linearity of expectation gives the
result.

*Interpretation.* `Q` is not an endpoint-local feature map: computing it requires an already validated pair and repair derivation. The theorem therefore covers only classifiers evaluated after this pair-conditioned quotienting step. It does not show that raw endpoints are label-blind, nor does it cover capsule spelling or formatting, certificate metadata, filenames, archive layout, a richer native semantics, or features omitted by a future translation. The designated pair side / repair polarity is intentionally label-bearing and reaches accuracy one. The result is a checked quotient property, not evidence that a learning system reasons about security.

## Theorem 4: Packet-only source-mapping indistinguishability

For any verifier whose decision depends only on an admitted finite pair packet,
there are two external source worlds that present the same packet while the packet
is a faithful abstraction in one world and not in the other. Therefore packet
acceptance alone cannot establish an unobserved source-to-profile mapping.

*Argument.* Fix an accepted packet. One external world associates it with endpoints
whose relevant executions refine the finite profile; another associates the same
packet with an endpoint or translation that omits a relevant behavior or state.
The verifier's input is identical, so its decision is identical, while fidelity
differs by construction. Additional translation evidence is necessary.

## Lemma 4: Source-capsule translation preservation

Let `C` be the syntax-directed compiler from a parsed `rcsc-source-1` capsule to the
admitted IR. For every parsed capsule `S`, every declared input `i`, and every
execution that remains within the shared dynamic bounds, direct source execution
and IR execution of `C(S)` have the same violation, abort bit, typed return value,
ordered typed event snapshots, projected public state, step count, and operation
trace.

*Proof.* Structural induction on source expressions establishes equality with their
compiled IR expressions. Literals, variables, and public-state reads are direct;
unary negation compiles to subtraction from zero; the remaining unary and binary
cases apply the identical typed operation to equal induction hypotheses. Induction
on the statement sequence then considers the fifteen statement constructors. Each
compiler clause emits exactly one IR instruction with the same role and operands,
and each pair of source/IR transition clauses performs the same state, environment,
event, control, monitor, and trace update. Terminal violation, abort, and return
states stop both sequences at the same instruction. Projection order is copied
from the source declaration. Hence the complete results agree. Parser and resource
rejection are outside the lemma's admitted-execution premise.

## Theorem 5: Source-bound pair lifting

If the source-pair verifier accepts source capsules `S_v,S_p`, supplied endpoints
`V,P`, a source certificate, and a pair certificate, then `V=C(S_v)` and
`P=C(S_p)` exactly, the source executions refine those endpoints as in Lemma 4,
and the source pair satisfies the strengthened finite pair relation through the
accepted endpoints.

*Proof sketch.* The verifier first parses and compiles each source capsule. Exact
structural comparison binds every source declaration and statement to the supplied
endpoint; the source certificate binds language, profile, family, pair id, and both
endpoint ids. Exhaustive source/IR replay checks Lemma 4's result on every declared
input before invoking the ordinary pair verifier. Theorem 1 then establishes the
strengthened relation and pair-certificate binding. Any parse failure, declaration
substitution, source/IR difference, execution mismatch, dynamic execution failure,
or pair-certificate failure rejects. Dynamic failures are reported as a structured
source-layer rejection rather than escaping the verifier. This theorem applies only
to `rcsc-source-1`; it is not a refinement theorem
from C, C++, Solidity, or EVM.

## Proposition 2: Necessity and identity controls

The principal gates are logically distinct from finite semantic success.

*Counterexamples.* In the empty-safe-domain program, every input violates in `V`;
an always-aborting `P` satisfies closure and vacuous safe equality. Removing the
safe-input clause accepts it. In the pre-root-abort case, one input violates but
the only nonviolating input aborts in shared context before every root instruction;
counting that execution as the safe witness accepts a relation with no benign root
execution. In the root-label case, context and semantics agree
but unrelated root no-op tags encode the endpoint label. Removing exact repair
membership accepts it, and the pair-conditioned admitted-IR repair quotient is no longer shared. In the
third case, a division guard is semantically equivalent to nonzero checking on the
finite domain but uses an undeclared predicate syntax rather than containing the
named `denominator != 0` conjunct. A relation that checks only erasure and semantic
outcomes accepts it; exact named-repair membership rejects it. The third control is
about the identity of a declared finite edit relation, not a claim that the
alternative guard is insecure.

The production relation rejects the four cases with `missing-safe-input`,
`missing-productive-safe-input`, `root-repair-mismatch`, and
`root-repair-mismatch`, respectively. Extra conjuncts
inside an otherwise canonical guard provide a separate control: repair membership
can pass while safe-observation equality rejects an over-restrictive patch. Thus
root binding, closure, and preservation do not substitute for one another.

## Proposition 3: Complete fixed-feature witnesses

The context diagnostic has fourteen named features. Enumerating all nonempty
subsets in increasing cardinality and lexical order examines `2^14 - 1 = 16,383`
subsets. Therefore the first perfect separator is globally minimum-cardinality
within that universe; if none is found, no subset of those features perfectly
separates labels.

This proposition does not claim a causal explanation, a minimum syntax edit, or a
globally smallest witness across structural, semantic, and resource failures.

## Exact finite execution evidence

The order/type grammar contains 288 program pairs. Its semantic observer relation
accepts exactly twenty and rejects 268. The production strengthened relation
accepts six grammar pairs because 282 lack the exact family repair; this is an
intentional layer distinction. Across 4,608 endpoint valuations, the two repaired
evaluators match the immutable-state observation oracle in 9,216 comparisons.
Faulty observers admit 16 aliasing-only, 20 untyped-only, and 52 combined false
acceptances.

A separate full-language reference interpreter imports no project schema, value,
evaluator, generator, checker, or repair code. It operates only after production
admission, uses immutable type-tagged values, and independently implements every
frozen instruction and expression operation. The retained campaign covers all
operations and expression forms across 2,834 programs and 21,002 valuations. Both
production evaluators match its semantic tuple, step count, and operation trace in
all 42,004 comparisons. This is complete coverage of the operation catalogue on
the retained program set, not exhaustive enumeration of all well-formed programs
and not an independent check of parsing, admission, resource limits, or pair
logic.

A second finite execution check targets the boundary that catalogue coverage alone
does not quantify: dynamic definedness. The frozen expression matrix enumerates
1,596 operator/value cases and includes 945 errors; the instruction matrix runs
1,013 valuations of twenty admitted microprograms and includes 425 errors. Across
all 2,609 cases (7,827 interpreter evaluations), producer, consumer, and immutable
reference agree on definedness, and all defined cases agree on the exact tagged or
operational result. This is exact for the declared matrices. It neither proves
agreement on every admitted program nor identifies exception classes or messages
as part of the object-language semantics.

The constructor grid has 96 pairs and 384 expected certificate variants, all
matching. The description oracle covers exactly ten declared predicate
abstractions and 184 evaluator comparisons. These exact results prove their finite
case partitions or retained cross-checks, not general implementation correctness.

The source campaign contains sixty owned source pairs and 120 textual programs,
covering every source statement and expression operation. Across 860 endpoint
valuations, the direct immutable source interpreter agrees with the two production
IR evaluators and the immutable IR reference in 2,580 semantic and operational
comparisons. Fifty-five controls alter source-certificate fields, substitute a
source endpoint or compiled IR, duplicate a declaration, add an extra root edit,
substitute the pair witness, introduce an admitted dynamic type error, or propagate
a pair whose only nonviolating execution aborts before root; every control rejects
for its expected layer. These
checks independently exercise the implementation boundary of Lemma 4 and Theorem 5
on the retained corpus; they do not replace the case analysis or generalize to a
native language.

## Trusted base and unproved extensions

The trusted base includes domain and projection declarations, root/context roles,
monitor meaning, JSON parser/admission, resource enforcement, canonical packet
interpretation, and the host runtime. Producer/consumer agreement alone is not
independent evidence because those evaluators share several components. The
standalone reference interpreter materially narrows the execution-semantic trusted
base for retained admitted programs, while the exact observation grammar provides
a stronger complete partition for the observer-specific risk. No mechanized proof
connects either executable reference to every possible admitted packet.

The delivered source-capsule extension supplies a separate parser, compiler,
direct source semantics, translation-preservation argument, and retained finite
cross-check for its own one-to-one syntax. Extending that bridge to native C, C++,
Solidity, or EVM would still require a source-language semantics and refinement
argument for unsupported behaviors such as pointers, undefined behavior,
transactions, gas, and external call trees. None of those native-language claims is
supplied.
