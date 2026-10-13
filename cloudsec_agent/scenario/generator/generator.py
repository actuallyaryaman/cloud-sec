__all__ = [
    "generate_scenario",
    "scenario_id_for",
]

from . import naming
from .families import build_family
from .models import (DIFFICULTY_EASY, FAMILIES, SUPPORTED_VERSIONS,
                     ExpectedState, GeneratedScenario, GroundTruth,
                     LogEventSpec, SeedManifest)
from .models import EvidenceObject as _EvidenceObject


def scenario_id_for(version, family, difficulty, seed) -> str:
    token = f"seed-{seed:04d}" if isinstance(seed, int) and seed >= 0 \
        else f"seed-{seed}"
    return f"{version}:{family}:{difficulty}:{token}"


def generate_scenario(generator_version, seed, family,
                      difficulty=DIFFICULTY_EASY) -> GeneratedScenario:
    if generator_version not in SUPPORTED_VERSIONS:
        raise ValueError("unknown generator version")
    if family not in FAMILIES:
        raise ValueError("unknown family")
    from .models import DIFFICULTIES
    if difficulty not in DIFFICULTIES:
        raise ValueError("unknown difficulty")
    rng = naming.spawn_rng(generator_version, family, difficulty, seed)
    medium = difficulty != DIFFICULTY_EASY
    built = build_family(family, rng, medium)
    resources = built["resources"]
    scenario_id = scenario_id_for(generator_version, family, difficulty,
                                  seed)
    objects = tuple(
        _EvidenceObject(key=item["key"], body=item["body"],
                        evidence_ref=f"{scenario_id}:obj:{index:04d}")
        for index, item in enumerate(built["objects"]))
    log_events = tuple(
        LogEventSpec(
            ref=f"{scenario_id}:ev:{index:04d}",
            actor=item["actor"],
            actor_access_key_id=None,
            operation=item["operation"], target=item["target"],
            result=item["result"],
            key_ref="incident" if item.get("key") == "incident" else None)
        for index, item in enumerate(built["events"]))
    if built["malicious"]:
        truth = GroundTruth(
            malicious=True, principal=built["principal"],
            key_owner=built["key_owner"],
            action_tool_id="update_access_key",
            action_arguments={"UserName": built["principal"],
                              "Status": "Inactive"},
            actor_to_principal=dict(built["actor_map"]),
            label=built["truth_label"])
    else:
        truth = GroundTruth(malicious=False, label=built["truth_label"])
    expected = ExpectedState(
        users=(resources["incident_user"], resources["investigator_user"]),
        incident_key_active_count=1, investigator_key_active_count=1,
        object_keys=tuple(item["key"] for item in built["objects"]),
        log_event_count=len(built["events"]),
        secret_name=resources["secret_name"],
        function_name=resources["function_name"],
        policy_name=resources["incident_policy"])
    variation = {
        "actor_labels": sorted({item["actor"] for item in built["events"]}),
        "operations": sorted({item["operation"]
                              for item in built["events"]}),
        "object_count": len(built["objects"]),
        "event_count": len(built["events"]),
    }
    manifest = SeedManifest(
        generator_version=generator_version, seed=seed, family=family,
        difficulty=difficulty, scenario_id=scenario_id,
        variation=variation)
    briefing_text = (
        f"Review storage bucket {resources['bucket']} and log location "
        f"{resources['log_group']}/{resources['log_stream']} for "
        f"suspicious activity.{built['briefing_note']}")
    return GeneratedScenario(
        generator_version=generator_version, seed=seed, family=family,
        difficulty=difficulty, scenario_id=scenario_id,
        bucket=resources["bucket"],
        incident_user=resources["incident_user"],
        investigator_user=resources["investigator_user"],
        incident_policy=resources["incident_policy"],
        secret_name=resources["secret_name"],
        function_name=resources["function_name"],
        log_group=resources["log_group"],
        log_stream=resources["log_stream"],
        objects=objects, log_events=log_events, ground_truth=truth,
        expected=expected, manifest=manifest,
        briefing_text=briefing_text)
