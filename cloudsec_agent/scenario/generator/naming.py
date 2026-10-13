__all__ = [
    "USER_WORDS",
    "spawn_rng",
    "hex_token",
    "user_name",
    "investigator_name",
    "bucket_name",
    "object_key",
    "policy_name",
    "secret_name",
    "function_name",
    "log_group",
    "log_stream",
    "actor_label",
    "benign_actor",
]

import random
import string

USER_WORDS = ("analytics-worker", "billing-job", "backup-agent",
              "report-service", "etl-runner", "audit-reader",
              "deploy-bot", "metrics-agent", "support-desk",
              "data-steward")

OBJECT_WORDS = ("reports", "notes", "exports", "summaries", "ledgers",
                "snapshots", "digests", "statements")

BENIGN_ACTORS = ("admin-console", "reporting-job", "deploy-pipeline",
                 "audit-cron")


def spawn_rng(version, family, difficulty, seed):
    return random.Random("|".join(
        [str(version), str(family), str(difficulty), str(seed)]))


def hex_token(rng, length=4) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(rng.choice(alphabet) for _ in range(length))


def user_name(rng) -> str:
    return f"{rng.choice(USER_WORDS)}-{hex_token(rng)}"


def investigator_name(rng) -> str:
    return f"case-investigator-{hex_token(rng)}"


def bucket_name(rng) -> str:
    return f"m7a-case-{hex_token(rng, 6)}"


def object_key(rng, prefix) -> str:
    return f"{prefix}/{rng.choice(OBJECT_WORDS)}-{hex_token(rng)}.txt"


def policy_name(rng, user) -> str:
    return f"{user}-case-read"


def secret_name(rng) -> str:
    return f"m7a-case-secret-{hex_token(rng, 6)}"


def function_name(rng) -> str:
    return f"m7a-case-fn-{hex_token(rng, 6)}"


def log_group(rng) -> str:
    return f"/m7a/case/{hex_token(rng, 6)}"


def log_stream(rng) -> str:
    return f"stream-{hex_token(rng, 6)}"


def actor_label(rng) -> str:
    return f"{rng.choice(('sess', 'ext'))}-{hex_token(rng, 8)}"


def benign_actor(rng) -> str:
    return rng.choice(BENIGN_ACTORS)
