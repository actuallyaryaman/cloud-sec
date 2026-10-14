__all__ = [
    "BENCHMARK_VERSION",
    "SCORING_VERSION",
    "SUPPORTED_VERSIONS",
    "CALIBRATION_SEEDS",
    "FAMILIES",
    "build_default_spec",
    "spec_to_dict",
    "spec_from_dict",
    "load_spec",
    "run_order",
]

import json
from . import BenchmarkSpec, ExperimentConfig, ScenarioCase

BENCHMARK_VERSION = "m7d-v1"
SCORING_VERSION = "m7d-eval-v1"
SUPPORTED_VERSIONS = ("m7d-v1",)

FAMILIES = ("credential_compromise", "recon_heavy", "data_access_anomaly",
            "benign")
DIFFICULTIES = ("easy", "medium")

CALIBRATION_SEEDS = (
    ("credential_compromise", "easy", 1),
    ("credential_compromise", "medium", 3),
    ("recon_heavy", "easy", 11),
    ("recon_heavy", "medium", 13),
    ("data_access_anomaly", "easy", 21),
    ("data_access_anomaly", "medium", 23),
    ("benign", "easy", 31),
    ("benign", "medium", 33),
)

PREVIOUSLY_USED_SEEDS = frozenset((1, 3, 11, 13, 21, 23, 31, 33))

HELD_OUT_START = 41
HELD_OUT_STEP = 2


def held_out_seeds(per_cell=2):
    out = {}
    cursor = HELD_OUT_START
    for family in FAMILIES:
        for difficulty in DIFFICULTIES:
            chosen = []
            while len(chosen) < per_cell:
                if cursor not in PREVIOUSLY_USED_SEEDS:
                    chosen.append(cursor)
                cursor += HELD_OUT_STEP
            out[(family, difficulty)] = tuple(chosen)
    return out


def _scenario_id(family, difficulty, seed):
    return f"m7a-v1:{family}:{difficulty}:seed-{seed:04d}"


def build_default_spec(config, per_cell=2):
    held = held_out_seeds(per_cell)
    cases = []
    for family in FAMILIES:
        for difficulty in DIFFICULTIES:
            for seed in held[(family, difficulty)]:
                cases.append(ScenarioCase(
                    family=family, difficulty=difficulty, seed=seed,
                    scenario_id=_scenario_id(family, difficulty, seed),
                    malicious=family != "benign", calibration=False))
    for family, difficulty, seed in CALIBRATION_SEEDS:
        cases.append(ScenarioCase(
            family=family, difficulty=difficulty, seed=seed,
            scenario_id=_scenario_id(family, difficulty, seed),
            malicious=family != "benign", calibration=True))
    return BenchmarkSpec(
        version=BENCHMARK_VERSION,
        generator_version=config.generator_version,
        scoring_version=SCORING_VERSION, repetitions=3, min_evaluable=2,
        cases=tuple(cases), config=config,
        scheduler={"name": "interleaved-coprime", "step": 3,
                   "version": "m7d-sched-v1"})


def run_order(spec, held_out_only=True):
    cases = [c for c in spec.cases
             if (not c.calibration) or not held_out_only]
    cells = sorted({(c.family, c.difficulty) for c in cases})
    step = spec.scheduler.get("step", 3)
    order = []
    for rep in range(1, spec.repetitions + 1):
        for position in range(len(cells)):
            family, difficulty = cells[(position * step) % len(cells)]
            for case in sorted(
                    (c for c in cases if c.family == family and
                     c.difficulty == difficulty),
                    key=lambda c: c.seed):
                order.append((case, rep))
    return order


def spec_to_dict(spec) -> dict:
    return {
        "version": spec.version,
        "generator_version": spec.generator_version,
        "scoring_version": spec.scoring_version,
        "repetitions": spec.repetitions,
        "min_evaluable": spec.min_evaluable,
        "max_consecutive_interruptions":
            spec.max_consecutive_interruptions,
        "min_attempts_for_rate": spec.min_attempts_for_rate,
        "max_interruption_rate": spec.max_interruption_rate,
        "scheduler": dict(spec.scheduler),
        "config": {
            "provider": spec.config.provider, "model": spec.config.model,
            "adapter_version": spec.config.adapter_version,
            "prompt_version": spec.config.prompt_version,
            "temperature": spec.config.temperature,
            "max_output_tokens": spec.config.max_output_tokens,
            "retries": spec.config.retries,
            "generator_version": spec.config.generator_version,
            "routing_mode": spec.config.routing_mode,
            "models": list(spec.config.models)},
        "cases": [{
            "family": c.family, "difficulty": c.difficulty, "seed": c.seed,
            "scenario_id": c.scenario_id, "malicious": c.malicious,
            "calibration": c.calibration} for c in spec.cases],
    }


def spec_from_dict(payload) -> BenchmarkSpec:
    version = payload.get("version")
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"unknown benchmark version: {version!r}")
    config = payload["config"]
    return BenchmarkSpec(
        version=version,
        generator_version=payload.get(
            "generator_version", config["generator_version"]),
        scoring_version=payload.get("scoring_version", SCORING_VERSION),
        repetitions=int(payload.get("repetitions", 3)),
        min_evaluable=int(payload.get("min_evaluable", 2)),
        cases=tuple(ScenarioCase(
            family=c["family"], difficulty=c["difficulty"],
            seed=int(c["seed"]), scenario_id=c["scenario_id"],
            malicious=bool(c["malicious"]),
            calibration=bool(c.get("calibration", False)))
            for c in payload["cases"]),
        config=ExperimentConfig(
            provider=config["provider"], model=config["model"],
            adapter_version=config["adapter_version"],
            prompt_version=config["prompt_version"],
            temperature=float(config["temperature"]),
            max_output_tokens=int(config["max_output_tokens"]),
            retries=int(config["retries"]),
            generator_version=config["generator_version"],
            routing_mode=str(config.get("routing_mode", "pinned")),
            models=tuple(config.get("models", ()))),
        max_consecutive_interruptions=int(payload.get(
            "max_consecutive_interruptions", 3)),
        min_attempts_for_rate=int(payload.get("min_attempts_for_rate", 10)),
        max_interruption_rate=float(payload.get(
            "max_interruption_rate", 0.20)),
        scheduler=dict(payload.get("scheduler", {})))


def load_spec(path) -> BenchmarkSpec:
    with open(path, encoding="utf-8") as handle:
        return spec_from_dict(json.load(handle))
