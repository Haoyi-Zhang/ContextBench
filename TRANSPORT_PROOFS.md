# Context-transport contract and proofs

This document states the mathematical contract implemented by `rcsc/transport.py`.
It is a proof argument, not a machine-checked verification of the Python program.
The finite operational semantics and the exact repair catalogue are in `SPECIFICATION.md`
and `PROOFS.md`. Relational framing, noninterference, and abstract interpretation
are established methods; the result here specializes them to a consumer-checked
benchmark transport protocol. Certificate tables do not create a new general
program logic and are not the source of the factorization speedup.

## 1. Objects and quantifiers

An admitted endpoint has a fixed initial public store, scalar input domains,
a sequence of instructions, a vulnerability-family monitor, and an observation
projection. Partition its input variables into R and N. Write D_R and D_N for
their nonempty Cartesian domains. An empty set of nuisance variables denotes a
one-element Cartesian product, not an empty input set. An ordinary endpoint
packet contains one anchor value for each variable in N. The transport packet
separately supplies each finite nuisance domain, containing that anchor.

For every n in D_N, let P_b[n] be the ordinary admitted program obtained by
replacing each nuisance singleton by the singleton containing n's value. It
retains D_R. The claim concerns the family of these programs; it does not create
one ordinary program whose admitted domain exceeds the ordinary replay cap.
The admitted scalar syntax bounds, instruction/variable counts, and tree node
counts continue to hold after substitution. Per-run totality and value budgets
are additionally checked below. No external source-language semantics is implied.

Write P_b = A ; K_b ; Z, for b in {V,P}. A and Z are common context sequences;
K_V and K_P are the contiguous root blocks. `Exec(P_b,r,n)` is the declared
finite execution, including monitor violation, abort, returned value, ordered
emission-time snapshots, projected public state, and operational trace. A runtime
error is not a safe execution. Observations compare abort, returned value, event
snapshots, and projected public state using injective type tags. Steps and monitor
traces support execution cross-checks but are not nonsecurity observations.

Define H_b(r,n) = (violation, abort) of this execution. Context transport requires:

1. All executions for r in D_R and n in D_N are defined within the declared value
   and allocation bounds.
2. There exist functions h_b such that H_b(r,n) = h_b(r) for all r,n. Thus varying
   nuisance inputs cannot alter either endpoint's security/abort profile.
3. The patched violation component is always empty; vulnerable violations, if
   any, are precisely the declared monitor kind.
4. There is one root input r_bad for which every n gives the declared vulnerable
   violation, and one root input r_good for which every n gives a nonaborting,
   nonviolating vulnerable execution completing all root instructions.
5. For every r,n for which the vulnerable execution is nonviolating, including
   aborting executions, Obs(P_V,r,n) = Obs(P_P,r,n).
6. The pair belongs to the exact named repair relation, with all required endpoint
   and submitted witness claims bound by the production checker.

There is deliberately no equality requirement between Obs(P_b,r,n) and
Obs(P_b,r,n') when n differs from n'. Functionality may vary with context.
The universal quantifiers concern declared inputs and checked context syntax,
not arbitrary wrappers, native-language programs, filenames, or model behavior.

## 2. Consumer-checked sufficient fragment

The consumer derives the following information; incoming annotations cannot
replace these checks.

* The complete declarations/context skeleton agree between endpoints. Deleting
  or reversing the declared repair reconstructs the vulnerable stream according
  to the existing repair catalogue. Root placement is separately checked.
* Both root blocks are contiguous, contain at most 24 instructions, and contain
  no emit or return. All root instructions belong to the declared finite profile.
* The shared prefix and suffix total at most 128 instructions. They contain only
  no-op, assignment, emission, and return; return is permitted only at the suffix
  end. There are no context monitors, guards, calls, public writes, loops, or
  pre-root exits.
* Let Read and Write be the union of both root blocks' local-variable footprints.
  Reads include expression variables and implicit monitor dependencies: sender
  for protected writes, account for balance operations, reenter for callback
  monitoring even when absent and defaulting to false, and the low-call success
  input. Prefix assignments are disjoint from Read union Write. N is disjoint
  from this same set.
* There are at most 128 root valuations, 32 nuisance variables, and 32 explicitly
  listed scalar values per nuisance variable. Values are type-distinct.
* Abstract interpretation establishes totality and conservative allocation bounds
  for the entire prefix and for the suffix after each normally terminating root
  result. It does not merely check the anchor execution.

These conditions are sufficient, not necessary. Identity assignments to protected
inputs, constant-true prefix guards, and root emissions can be harmless but lie
outside this fragment. Rejection on a frame or abstract-domain test is not a
semantic counterexample. The executable evidence retains such rejections.

## 3. Root table and the checked interface

For each root valuation r, the untrusted producer supplies the two root execution
results. The consumer constructs its own probe program: execute K_b, then on normal
completion emit every root-readable or root-written local that exists, and expose
**every** public-store key. Probe emissions are separate from program observations;
they exist only in the root-table proof object. Original roots contain no emits,
so a probe entry has no ambiguous producer-chosen event source.

The table binds the profile, family, original root-domain declaration, full initial
public state, both complete root instruction trees, and reconstructed read/write
sets. It does not bind a particular A or Z, permitting reuse across wrappers that
pass their own checks. The consumer enumerates all root valuations in canonical
order, independently re-executes both probe programs, and compares each entire row
with type-distinct equality. Missing, duplicate, reordered, or altered rows fail.
A different domain order requires a corresponding exact binding, although replay
visits the same canonical valuation order.

For every nonviolating vulnerable row, abort/return/probe-event/public-state
components must equal the patched row. A normal row therefore gives equality of
all root-accessible locals and all public state. For an aborting row, neither side
can execute a suffix, so abort and complete public-state equality suffice. There
must be a declared vulnerable witness row and a normal safe row. Patched rows may
not violate. Execution errors fail closed.

The producer uses the immutable reference evaluator to generate rows. The consumer
uses the production consumer evaluator. Probe construction is shared protocol
infrastructure, not an independently implemented parser or whole-system proof.
A separate full-program Cartesian semantic oracle avoids the footprint,
context abstraction, and root-table routines. It executes every root/context
point, checks definedness, declared-monitor consistency, patched closure,
within-context observations, uniform security/abort profiles, and both support
conditions, and compares retained primary executions with the immutable reference.
It deliberately does not decide exact repair membership, declaration equality,
or certificate claims. Each packet therefore carries a separately recorded
structural-precondition result. That gate invokes the production exact-repair
routine, so its repair result is shared-code evidence rather than an independent
second validator. A full contract classification is the conjunction of those
explicit structural premises and the Cartesian semantic result.

## 4. Totality and allocation lemmas

A bound is a set of possible value kinds, an integer interval when integers are
possible, and an upper bound on recursive JSON-tree nodes. Its concretization
contains runtime-admitted values of an allowed kind satisfying the applicable
interval and node constraints. The common runtime depth, text, and scalar bounds
are part of this concretization, not discarded by the abstraction. Initial bounds include every declared scalar input value and
the exact initial public values. Boolean and integer kinds are disjoint.

### Lemma 1 (total-expression abstraction)

If the expression checker accepts e in abstract stores Gamma and Pi, every concrete
store represented by Gamma and Pi gives a defined value for e, represented by the
returned bound, with charged-node cost at most the returned cost.

Proof. Induct on the admitted expression tree. Constants and variable/public
reads are bounded values in the corresponding abstract stores. The syntax check
and abstract environment ensure reads are defined. Addition and subtraction use
interval endpoint arithmetic; multiplication uses the minimum and maximum of the
four endpoint products. The consumer requires integer-only operands, so Boolean
values cannot enter integer arithmetic. These interval rules overapproximate every
concrete integer result. Acceptance requires the interval extrema to fit the
runtime integer bit bound; every enclosed result therefore fits. Integer ordering
returns a Boolean. Type-tagged equality and inequality are defined on every pair
of admitted JSON values; logical operations use total truth conversion and also
return a Boolean. Negation is the analogous unary case. The cost sums operand
costs plus at most the result's node charge. Reads of a compound value retain its
node bound. No context expression constructs a deeper compound container, and
all copied source values satisfy the admitted depth/text bounds. Thus value shape,
type, and cost claims hold at the parent. This covers all twelve operators. QED.

### Lemma 2 (total context and preserved frame)

An accepted context sequence executes every instruction up to its optional final
return, raises no dynamic or resource error within its checked budget, and changes
only its assigned locals and the emitted/returned observations. Its resulting
abstract local store encloses every resulting concrete store.

Proof. Induct on the instruction sequence using Lemma 1. A no-op changes nothing.
Assignment updates only its destination bound. Emission snapshots a bounded value;
the extra snapshot charge is included conservatively. Return similarly evaluates
its value and is terminal by the syntax check. There are no guards, aborts,
monitors, or public writes in the sequence. Summing instruction charges proves the
cost bound. The write-set restriction is checked independently, so the prefix
cannot modify any root-readable or root-written local. QED.

The allocation guard is not an assumption of unbounded host arithmetic. Let
C_A and C_Z be accepted context cost bounds. Root replay fixes the values of every
expression independent of n, and each admitted runtime value has at most 8192
nodes. A conservative root charge C_K is 8192 times the larger number of expression
nodes in the two root blocks. C_0 covers both initial dictionaries and their values,
plus 8192 nodes per final public field. Acceptance requires

    C_0 + C_A + C_K + max(normal root results) C_Z <= 500000.

The first two dictionaries contribute one node each. Every projection field is
charged separately by the evaluator, as reflected in C_0. Root operations without
expressions perform no additional budgeted value copy. Every root expression's
values are independently checked by replay. Consequently the sum bounds all
charged nodes in every complete contextual execution. Individual value bit, node,
text and depth constraints are preserved by Lemma 1 and checked core execution.
An operational deadline may still reject an otherwise valid computation; the
soundness theorem is about acceptances, not a wall-clock termination guarantee.

A subtle sequencing requirement is important: suffix analysis starts with the
abstract store **after A**, then overrides only root-probed locals with exact root
exit values. It must not reset all enumerated input variables to their entry
values. A prefix can legally overwrite an input that the root never reads; that
value can still affect suffix definedness. The regression suite includes this
case and rejects a hidden string-to-integer arithmetic error.

## 5. Root independence and contextual lifting

### Lemma 3 (root independence)

For a fixed r, executing either root inside any accepted context on (r,n) has the
same monitor status, abort status, root-accessible locals and public exit store as
its probe execution, for every n in D_N.

Proof. By Lemma 2 the prefix terminates normally, does not write the public store,
and does not modify Read union Write. N has no intersection with that union. All
root reads consequently see exactly the same values as in the probe. This includes
implicit reads and defaults in monitor instructions. The initial call-monitor
flags are the same: prefixes contain no instructions that modify them. Induct on
root instructions. Their next control/status decision and local/public update
are deterministic functions of these matching values. Thus they make the same
transition in the probe and contextual run. Both stop at the same root violation
or abort, or finish with matching root-accessible and public state. The previous
allocation argument ensures that the surrounding context cannot consume enough
budget to introduce a new failure. QED.

### Theorem 1 (context-transport soundness)

Every accepted production transport packet satisfies all six properties in
Section 1 for every declared n, including nuisance combinations not replayed by
the consumer.

Proof. Admission and exact edit reconstruction establish the identity and repair
part. Lemmas 1--3 establish totality, root independence, and invariant monitor/abort
profiles; suffixes neither change monitor status nor abort. Complete row coverage
and root replay establish patch closure and exclusion of the wrong monitor kind.
A violating root witness row lifts by Lemma 3 to the same violating root input at
every n. A normal safe row similarly yields a productive safe run at every n,
because both prefix and suffix are total and neither can skip the contiguous root.

For preservation, fix r,n with a nonviolating vulnerable execution. The two copies
of A start from identical complete input and public stores and are identical code,
so their states and prefix event sequences agree. If the roots abort, table
agreement supplies equal abort/public state; neither suffix runs. Otherwise table
agreement supplies equal root-written/readable locals and all public values.
Every remaining local is unchanged by both roots, and thus still equal from A.
The complete suffix-visible stores therefore agree. Determinism and Lemma 2 give
equal suffix emissions and returns. Combining the identical prefix observations,
no root emissions, and equal suffix observations proves typed observation equality.
Nothing in this argument equates the prefix or suffix observations for distinct
nuisance valuations. This proves the stated relation, not full-output
noninterference. QED.

### Corollary 1 (reuse under a different checked context)

The same root table can be used with any other shared prefix/suffix pair and
nuisance domain satisfying the consumer's checks with the same bound root objects.
The consumer still checks the new context and replays the table; there is no
trusted cache. Context identity is intentionally absent from the root binding,
but both root trees, root domains and initial public state must be identical.

### Corollary 2 (certificate elimination)

If all incoming identity and table claims are removed, an audit can reconstruct
the same framed relation by executing the same root rows and applying the same
structural/abstract conditions. It requires the same number of root executions.
A sound incoming table is a reusable inspectable evidence object, not stronger
semantic expressiveness or a further asymptotic speedup. The separate audit API
ignores incoming claims but retains all frame, exact-repair, closure, totality,
and nonvacuity obligations. It shares this reasoning implementation, so agreement
with it is not an independent soundness check.

## 6. Cost and evidence boundary

Let t = |D_R| and M = product_x |D_N(x)|. The semantic replay count is exactly
2t, compared with 2tM full endpoint executions. Reading explicit input lists and
checking each context are still required, and suffix analysis is repeated for at
most 2t normal root outcomes. The row table is independent of M for fixed root
binding. If s bounds serialized row size, its size is O(t s + binding size).

The implemented syntax checks are not all linear: exact repair checking can
compare multiple candidate edits, and a rejected guard can trigger a diagnostic
search over all erasures. These costs depend on bounded syntax size, not on the
Cartesian context count. No tight overall wall-time bound or improvement over
all symbolic relational verifiers is claimed. Measurements include admission,
repair checks, row comparison, abstract analysis and runtime overhead, so the
execution-count ratio must not be substituted for a measured speed ratio.

### Proposition 1 (no exact black-box extrapolation)

Consider a verifier with access only to queries of a Boolean predicate Good(n)
on M context values, and no structure restricting that predicate. If it must
accept every all-good instance and never accept an instance with a bad context,
then on the all-good instance it must query every context.

Proof. If an all-good execution accepts after fewer than M distinct queries,
choose an unqueried n*. Change only Good(n*) to false. The verifier sees exactly
the same answers on all its queries and follows the same execution, so it accepts
this bad instance, a contradiction. For a zero-error randomized verifier, positive-probability acceptance after fewer
than M queries must omit some fixed context with positive probability, since there
are only M possible contexts. Changing that answer creates a positive probability
of false acceptance. Thus every context must be queried almost surely. QED.

This is a query lower bound for an opaque predicate, not a lower bound for static
analysis, symbolic execution or relational program logics. Those methods can use
structure, as this checker does. It also does not prohibit probabilistic testing.
With a single uniformly located bad context, q distinct sampled values miss it
with probability (M-q)/M; that is a detection calculation, not a certificate.

## 7. Exact counterexamples and conservative exclusions

A division guard `denominator != 0 and n == 0` is an exact inserted guard containing
the required predicate. With n fixed to zero, it closes division by zero and
preserves all safe behavior; the existing anchor pair relation correctly accepts.
At n=1 it aborts even for a nonzero denominator, so the safe observations change.
The anchor verifier is not unsound for its domain. What fails is extrapolating
its result to a larger domain. The transport consumer reconstructs the added n
read and rejects the frame.

A common prefix that aborts only at n=1 leaves the anchored relation valid but
removes both root witnesses from that context. A prefix that changes a root input
can change monitor status. An unseen Boolean operand in integer arithmetic causes
a type error. Repeated squaring can exceed the bounded integer semantics. None can
be dismissed by shared-context equality; the transport frame/totality checks
reject them. Raw witnesses are retained with full context/root valuations.

Two additional scope mutations separate that semantic evidence from the relation
entry conditions. Appending one root-role `nop` to the patched division root leaves
all finite executions, observations, monitor outcomes, and profiles unchanged, so
the Cartesian semantic oracle accepts; exact repair membership and the production
entry reject `root-repair-mismatch`. Relabeling the same C-profile division pair as
`fixed_overflow` preserves its per-root profile constancy but makes the observed
`divide-by-zero` violation inconsistent with the declared monitor and also fails
the named repair. These two cases are recorded separately from the 76 transport
controls because they test oracle scope, not additional contextual attacks.

Conversely `denominator := denominator` before the root and a constant-true shared
prefix guard are valid for all inputs but rejected by the syntactic fragment.
The controlled experiment predeclares twelve such cases, two in each family.
The Cartesian semantic oracle, after separately confirming declaration/domain and
repair premises, additionally finds a semantically valid amount overwrite in the
callback family: both assigned amounts remain below the positive balance, so the
security profile and the paired observations are unchanged. The report therefore
counts thirteen valid-but-rejected controls, not twelve, and does not count that
frame rejection as attack detection. The applicability audit also retains the six
valid preexisting observer cases excluded by root-emission/placement restrictions.
No rejection is called a semantic defect without full Cartesian semantic replay
under recorded structural premises. These are not completeness claims.

## 8. Relation to earlier finite evidence

The existing finite pair/source/transform checks remain useful validation layers.
The pair-conditioned repair quotient's one-half result is a balance identity after
validated erasure, not a theorem about raw endpoint features and not evidence for
context transport. It is retained only as a diagnostic in the artifact. The new
transport theorem relies on reconstructed context effects and complete root exit
stores, not on that quotient or a lexical classifier. The source capsule remains
an optional project-defined textual representation with no native-language bridge.

## 9. Pointwise label constancy is strictly weaker

Let root input r and context n each range over {0,1}. Use the vulnerable operation 1/(r-n) and its canonical denominator-nonzero guard repair. At each n, r=n is a violating witness and r=1-n a productive safe witness. All nonviolating paired observations agree. Thus each point-instantiated pair satisfies the ordinary relation. However, the vulnerable profile changes from violating to safe at r=0 when n changes, and vice versa at r=1. No uniform bad or good witness exists. The contextual relation therefore fails despite valid labels and repairs at every point. The transport frame rejects the read of n in the root. `MovingWitnessTest` in `tests/test_transport.py` checks both pointwise acceptances, the direct oracle's pointwise relation, the changed security profile, and the frame rejection. This is a targeted proof regression, not an extra primary case in the 36-pair campaign.
