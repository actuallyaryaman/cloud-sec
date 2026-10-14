# M7D-v1 benchmark design note

Machine-readable spec: `benchmarks/m7d-v1.json` (built by
`cloudsec_agent.evaluation.spec.build_default_spec`, validated by
`load_spec`; unknown versions fail closed).

## Question

How reliably does the model investigate/respond correctly under a fixed
scenario distribution and trusted-control architecture — per run AND per
replicated scenario (3x default), not "did it succeed once".

## Size: SMALL first — 16 scenarios x 3 = 48 runs

FULL (24x3=72) deferred. Rationale, from R3 evidence only:

- R3 mean load 13,228 tokens/run → 48 runs ≈ 635k tokens (ROUGH PLANNING
  ESTIMATE), 72 runs ≈ 950k. 48 keeps a single execution milestone practical.
- R3 provider-interruption rate 3/12 (25%, transient). At 72 runs the
  expected interrupted mass (~18) threatens interpretability; validate
  handling at 48 first.
- 16 scenarios still cover 4 families x 2 difficulties x 2 held-out seeds;
  variance was already decisive at n=4 scenarios in R3.
- Expand to FULL only after Stage-1 harness reliability is confirmed.

## Seed selection (deterministic, predeclared)

Per (family, difficulty) cell: ascending odd seeds from 41, skipping every
previously model-visible seed {1,3,11,13,21,23,31,33}; take 2 (SMALL).
Pure function of cell index — no model-outcome information, so held-out
cases cannot be cherry-picked. Previously seen seeds exist ONLY as
CALIBRATION cases (harness comparability); headline scoring uses held-out.

## Ordering

Round-robin over 8 cells with step 3 (coprime to 8): no family/difficulty
repeats adjacently, repetitions maximally spread. Scheduler identity
(`m7d-sched-v1`, step) recorded in spec. No unrecorded randomness.

## Provider policy

Isolated interruptions are recorded, benchmark continues. Stop when: 3
consecutive interruptions, OR >20% interruptions after >=10 attempts.
Threshold separates model reliability from provider unusability and is
fixed before execution.

## Interruption semantics (R3 lesson, formalized)

Interrupted runs report `evaluable_runs` vs `attempted_runs` separately:
evaluable success = successes/evaluable, attempted success =
successes/attempted, provider completion = completed/attempted. Interrupted
runs NEVER count as cognitive failures. Minimum evaluable repetitions = 2
for a nominal 3-run design (1/1 is not "consistent").

## Scoring

Independent dimensions per run (infra / provider / contract / decision /
control / effective state); scenario aggregates with stability
(CONSISTENT_SUCCESS / CONSISTENT_FAILURE / MIXED /
INSUFFICIENT_EVALUABLE_RUNS); benchmark splits by family/difficulty/
malicious-benign/control/grounding. Benign FP counts even if controls
block it; valid-target control rejection is infrastructure-invalid, not
model failure. Grounding counts carry the plural-key/briefing undercount
caveat and never decide correctness alone.

## Provenance / artifacts / resumability

Per-run INDEPENDENTLY_RECOMPUTED (config/digests), RECORDED_RUNTIME
(model/control stream), LIVE_OBSERVED (post-submit state),
UNAVAILABLE_AFTER_TEARDOWN. Immutable RunKeys; existing run artifacts are
never silently overwritten; provider failures get new repetition identity
(prefer no replacement in v1). No secrets, no chain-of-thought.

## Resolved policies

- Prompt ceiling stays CEILING_REACHED; held-out results must not drive
  prompt tuning without a new agent/prompt version.
- New model/config = new experiment identity; never compare as identical.
- Statistics stay descriptive (counts/fractions/distributions; Wilson
  intervals only if correctly implemented and labeled).
