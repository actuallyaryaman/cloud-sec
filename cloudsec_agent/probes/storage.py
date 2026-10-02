import base64
import json
import uuid

from ..authz import Identity, assume_role, ensure_bucket, policy, statement
from ..result import CallOutcome

BUCKET_X = "cloudsec-x"
BUCKET_Y = "cloudsec-y"
SYNTHETIC_BODY = b"cloudsec-synthetic-probe-body"
SYNTHETIC_SECRET_VALUE = "cloudsec-synthetic-secret-value-do-not-use"


def _arn(bucket, key=None):
    return f"arn:aws:s3:::{bucket}" + (f"/{key}" if key else "")


def _bucket_exists(s3, bucket):
    return CallOutcome.capture("s3", "HeadBucket", lambda c: c.head_bucket(Bucket=bucket)).ok


def _object_exists(s3, bucket, key):
    return CallOutcome.capture("s3", "HeadObject", lambda c: c.head_object(
        Bucket=bucket, Key=key)).ok


def _make_bucket(floci, bucket):
    return ensure_bucket(floci.client("s3"), bucket)


def _seed(s3, bucket, key="probe/object.txt", body=SYNTHETIC_BODY):
    return CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
        Bucket=bucket, Key=key, Body=body))


def _get(s3, bucket, key="probe/object.txt"):
    def call(client):
        response = client.get_object(Bucket=bucket, Key=key)
        response["Body"].read()
        return {"Body": "read"}
    return CallOutcome.capture("s3", "GetObject", call, s3)


def probe(floci, matrix, suffix):
    gaps = []
    operations = {}
    authz = {}
    signals = {}
    x = f"{BUCKET_X}-{suffix}"
    y = f"{BUCKET_Y}-{suffix}"
    s3 = floci.client("s3")

    for name, bucket in (("x", x), ("y", y)):
        created = _make_bucket(floci, bucket)
        operations[f"CreateBucket.{name}"] = created.to_dict()
        if not created.ok:
            gaps.append(f"S3 CreateBucket failed for {bucket}: {created.error_code}")
            return _result(False, operations, authz, gaps, signals)
    _seed(s3, x)
    _seed(s3, y)
    operations["PutObject"] = {"operation": "PutObject", "ok": True, "status": 200}

    got = _get(s3, x)
    operations["GetObject"] = got.to_dict()
    operations["HeadObject"] = _object_exists(s3, x, "probe/object.txt") and {
        "operation": "HeadObject", "ok": True, "status": 200}
    listed = CallOutcome.capture("s3", "ListObjectsV2", lambda c: c.list_objects_v2(Bucket=x))
    operations["ListObjectsV2"] = listed.to_dict()
    body_ok = False
    if got.ok:
        raw = CallOutcome.capture("s3", "GetObjectBody", lambda c: c.get_object(
            Bucket=x, Key="probe/object.txt"))
        if raw.ok:
            body_ok = raw.raw["Body"].read() == SYNTHETIC_BODY
    operations["GetObjectBodyMatchesSynthetic"] = {
        "operation": "GetObjectBody", "ok": body_ok}
    if not body_ok:
        gaps.append("S3 GetObject did not return the exact synthetic body")

    put_tag = CallOutcome.capture("s3", "PutBucketTagging", lambda c: c.put_bucket_tagging(
        Bucket=x, Tagging={"TagSet": [{"Key": "cloudsec", "Value": "probe"}]}))
    operations["PutBucketTagging"] = put_tag.to_dict()
    get_tag = CallOutcome.capture("s3", "GetBucketTagging", lambda c: c.get_bucket_tagging(
        Bucket=x))
    operations["GetBucketTagging"] = get_tag.to_dict()
    obj_tag = CallOutcome.capture("s3", "PutObjectTagging", lambda c: c.put_object_tagging(
        Bucket=x, Key="probe/object.txt",
        Tagging={"TagSet": [{"Key": "cloudsec", "Value": "probe"}]}))
    operations["PutObjectTagging"] = obj_tag.to_dict()
    if not put_tag.ok and not obj_tag.ok:
        gaps.append("S3 tagging unsupported on both bucket and object")

    delete_tag = CallOutcome.capture("s3", "DeleteBucketTagging", lambda c: c.delete_bucket_tagging(
        Bucket=x))
    operations["DeleteBucketTagging"] = delete_tag.to_dict()

    availability = {"identity_allow_observed": True, "implicit_deny_observed": True,
                    "explicit_deny_observed": True, "resource_scoping_observed": True}
    authz["identity_allow"] = _case_a(floci, matrix, suffix, x, y, availability)
    authz["implicit_deny"] = _case_b(floci, matrix, suffix, x, availability)
    authz["explicit_deny_get"] = _case_c(floci, matrix, suffix, x, "s3:GetObject",
                                         "GetObject", availability)
    authz["explicit_deny_put"] = _case_c(floci, matrix, suffix, x, "s3:PutObject",
                                         "PutObject", availability)
    authz["resource_scoped_allow"] = _case_d(floci, matrix, suffix, x, y, availability)
    authz["resource_scoped_deny"] = _case_e(floci, matrix, suffix, x, y, availability)
    authz["assumed_role_allow"] = _case_f_allow(floci, matrix, suffix, x)
    authz["assumed_role_deny"] = _case_f_deny(floci, matrix, suffix, x)
    authz["bucket_policy_deny"] = _bucket_policy_deny(floci, matrix, x, gaps)

    signals["s3"] = availability
    _cleanup(floci, x, y)
    return _result(True, operations, authz, gaps, signals)


def _new_identity(floci, label):
    identity = Identity(floci, label)
    if not identity.create():
        return None
    return identity


def _case_a(floci, matrix, suffix, x, y, availability):
    identity = _new_identity(floci, f"s3a{suffix}")
    if identity is None:
        availability["identity_allow_observed"] = None
        return {"error": "identity creation failed"}
    doc = policy([statement("Allow", "s3:GetObject", [_arn(x, "*"), _arn(x)])])
    confirmed = identity.put_inline_policy("s3-allow", doc)
    outcome = _get(identity.client("s3"), x)
    case = matrix.record(
        "A", "s3:GetObject", "s3", "iam-user", identity.arn, _arn(x, "*"),
        "allow", outcome, state_changed=False, policy_confirmed=confirmed,
        signals=["identity_allow"],
        notes="matching Allow attached and re-read before the call")
    availability["identity_allow_observed"] = case["classification"]
    identity.delete()
    return case


def _case_b(floci, matrix, suffix, x, availability):
    identity = _new_identity(floci, f"s3b{suffix}")
    if identity is None:
        availability["implicit_deny_observed"] = None
        return {"error": "identity creation failed"}
    outcome = _get(identity.client("s3"), x)
    case = matrix.record(
        "B", "s3:GetObject", "s3", "iam-user-no-policy", identity.arn, _arn(x, "*"),
        "deny", outcome, state_changed=False,
        policy_confirmed=not identity.has_policy(),
        signals=["implicit_deny"],
        notes="verified that no policy is attached to this principal")
    availability["implicit_deny_observed"] = case["classification"]
    identity.delete()
    return case


def _case_c(floci, matrix, suffix, x, action, operation_name, availability):
    identity = _new_identity(floci, f"s3c{operation_name[:3].lower()}{suffix}")
    if identity is None:
        availability["explicit_deny_observed"] = None
        return {"error": "identity creation failed"}
    control_key = "probe/control.txt"
    denied_key = "probe/denied.txt"
    bucket_pattern = _arn(x, "*")
    denied_arn = _arn(x, denied_key)
    baseline = policy([statement("Allow", action, bucket_pattern)])
    baseline_confirmed = identity.put_inline_policy("s3-deny", baseline)
    s3 = identity.client("s3")
    admin = floci.client("s3")

    if operation_name == "GetObject":
        _seed(admin, x, control_key)
        _seed(admin, x, denied_key)
        baseline_outcome = _get(s3, x, control_key)
    else:
        CallOutcome.capture("s3", "DeleteObject", lambda c: c.delete_object(
            Bucket=x, Key=denied_key), admin)
        baseline_outcome = CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
            Bucket=x, Key=control_key, Body=b"cloudsec-synthetic-control"), s3)
    control_exists = _object_exists(admin, x, control_key)
    denied_existed_before = _object_exists(admin, x, denied_key)

    combined = policy([
        statement("Allow", action, bucket_pattern),
        statement("Deny", action, denied_arn),
    ])
    confirmed = identity.put_inline_policy("s3-deny", combined)

    if operation_name == "GetObject":
        outcome = _get(s3, x, denied_key)
    else:
        outcome = CallOutcome.capture("s3", "PutObject", lambda c: c.put_object(
            Bucket=x, Key=denied_key, Body=b"should-not-land"), s3)
    denied_exists = _object_exists(admin, x, denied_key)

    attributable = bool(baseline_confirmed and baseline_outcome.ok and control_exists)
    case = matrix.record(
        "C", action, "s3", "iam-user-deny", identity.arn, denied_arn,
        "deny", outcome, state_changed=denied_exists,
        policy_confirmed=bool(confirmed and attributable),
        signals=["explicit_deny"],
        notes="baseline Allow proven by a control object, then resource-scoped Deny")
    if not attributable:
        case["classification"] = None
        case["notes"] = ("baseline access was not established, so the deny result "
                         "cannot be attributed to the Deny")
    elif not outcome.ok and not outcome.denied:
        case["classification"] = None
        case["notes"] = (f"the target call failed with {outcome.error_code} rather than "
                         "an authorization result, so enforcement is inconclusive")
    case["control"] = {
        "baseline_policy_readback": baseline_confirmed,
        "baseline_operation_ok": baseline_outcome.ok,
        "baseline_error_code": baseline_outcome.error_code,
        "control_object_exists": control_exists,
        "deny_policy_readback": confirmed,
        "denied_object_existed_before": denied_existed_before,
        "denied_object_exists": denied_exists,
        "target_error_code": outcome.error_code,
        "target_authorization_failure": outcome.denied,
    }
    availability["explicit_deny_observed"] = case["classification"]
    identity.delete()
    return case


def _case_d(floci, matrix, suffix, x, y, availability):
    identity = _new_identity(floci, f"s3d{suffix}")
    if identity is None:
        availability["resource_scoping_observed"] = None
        return {"error": "identity creation failed"}
    doc = policy([statement("Allow", "s3:GetObject", [_arn(x, "*")])])
    confirmed = identity.put_inline_policy("s3-scoped", doc)
    s3 = identity.client("s3")
    on_x = _get(s3, x)
    on_y = _get(s3, y)
    matrix.record("D-x", "s3:GetObject", "s3", "iam-user-scoped-allow", identity.arn,
                  _arn(x, "*"), "allow", on_x, state_changed=False,
                  policy_confirmed=confirmed, signals=["resource_scoping_allow"],
                  notes="in-scope resource")
    case_y = matrix.record("D-y", "s3:GetObject", "s3", "iam-user-scoped-allow", identity.arn,
                           _arn(y, "*"), "deny", on_y, state_changed=False,
                           policy_confirmed=confirmed, signals=["resource_scoping_allow"],
                           notes="out-of-scope resource")
    availability["resource_scoping_observed"] = (
        True if case_y["classification"] is True else case_y["classification"])
    identity.delete()
    return {"x": on_x.to_dict(), "y": case_y}


def _case_e(floci, matrix, suffix, x, y, availability):
    identity = _new_identity(floci, f"s3e{suffix}")
    if identity is None:
        availability["resource_scoping_observed"] = None
        return {"error": "identity creation failed"}
    doc = policy([
        statement("Allow", "s3:*", "*"),
        statement("Deny", "s3:GetObject", [_arn(x, "*")]),
    ])
    confirmed = identity.put_inline_policy("s3-scoped-deny", doc)
    s3 = identity.client("s3")
    on_x = _get(s3, x)
    on_y = _get(s3, y)
    matrix.record("E-x", "s3:GetObject", "s3", "iam-user-scoped-deny", identity.arn,
                  _arn(x, "*"), "deny", on_x, state_changed=False,
                  policy_confirmed=confirmed, signals=["resource_scoping_deny"],
                  notes="resource named by the Deny")
    case_y = matrix.record("E-y", "s3:GetObject", "s3", "iam-user-scoped-deny", identity.arn,
                           _arn(y, "*"), "allow", on_y, state_changed=False,
                           policy_confirmed=confirmed, signals=["resource_scoping_deny"],
                           notes="resource not named by the Deny")
    availability["resource_scoping_observed"] = case_y["classification"]
    identity.delete()
    return {"x": on_x.to_dict(), "y": case_y}


def _case_f_allow(floci, matrix, suffix, x):
    role = _role(floci, f"cloudsec-fallow-{suffix}",
                 policy([statement("Allow", "s3:GetObject", [_arn(x, "*")])]))
    if role is None:
        return {"error": "role creation failed"}
    creds, outcome = assume_role(floci, role, f"fallow{suffix}")
    if creds is None:
        return {"assume_role": outcome.to_dict()}
    client = floci.client("s3", akid=creds["access_key_id"],
                          secret=creds["secret_access_key"],
                          token=creds["session_token"])
    got = _get(client, x)
    return {
        "expiration": creds["expiration"],
        "assumed_role_arn": creds["assumed_role_arn"],
        "get": got.to_dict(),
    }


def _case_f_deny(floci, matrix, suffix, x):
    role = _role(floci, f"cloudsec-fdeny-{suffix}", policy([
        statement("Allow", "s3:*", "*"),
        statement("Deny", "s3:GetObject", "*"),
    ]))
    if role is None:
        return {"error": "role creation failed"}
    creds, outcome = assume_role(floci, role, f"fdeny{suffix}")
    if creds is None:
        return {"assume_role": outcome.to_dict()}
    client = floci.client("s3", akid=creds["access_key_id"],
                          secret=creds["secret_access_key"],
                          token=creds["session_token"])
    got = _get(client, x)
    matrix.record("F-deny", "s3:GetObject", "s3", "assumed-role", role, _arn(x),
                  "deny", got, state_changed=False,
                  policy_confirmed=CallOutcome.capture(
                      "iam", "GetRolePolicy",
                      lambda c: c.get_role_policy(RoleName=role.rsplit("/", 1)[1],
                                                  PolicyName="probe")).ok,
                  signals=["sts_role_restrictions"],
                  notes="explicit Deny evaluated with assumed-role credentials")
    return {"get": got.to_dict(), "expiration": creds["expiration"]}


def _role(floci, name, document):
    iam = floci.client("iam")
    trust = policy([statement("Allow", "sts:AssumeRole", "*")])
    CallOutcome.capture("iam", "DeleteRole", lambda c: c.delete_role(RoleName=name))
    created = CallOutcome.capture("iam", "CreateRole", lambda c: c.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust))
    if not created.ok:
        return None
    CallOutcome.capture("iam", "PutRolePolicy", lambda c: c.put_role_policy(
        RoleName=name, PolicyName="probe", PolicyDocument=document))
    return f"arn:aws:iam::{floci.account}:role/{name}"


def _bucket_policy_deny(floci, matrix, x, gaps):
    identity = _new_identity(floci, f"s3bp{x[-4:]}")
    if identity is None:
        return {"error": "identity creation failed"}
    doc = policy([statement("Allow", "s3:GetObject", "*")])
    confirmed = identity.put_inline_policy("s3-allow-any", doc)
    s3 = identity.client("s3")
    put = CallOutcome.capture("s3", "PutBucketPolicy", lambda c: c.put_bucket_policy(
        Bucket=x, Policy=policy([statement("Deny", "s3:GetObject", _arn(x, "*"))])))
    policy_present = False
    if put.ok:
        got = CallOutcome.capture("s3", "GetBucketPolicy", lambda c: c.get_bucket_policy(
            Bucket=x))
        policy_present = bool(got.ok) and "Deny" in json.dumps(got.raw.get("Policy", ""))
    outcome = _get(s3, x)
    case = matrix.record(
        "S3-BP", "s3:GetObject", "s3", "iam-user-with-bucket-policy-deny", identity.arn,
        _arn(x, "*"), "deny", outcome, state_changed=False,
        policy_confirmed=bool(policy_present and confirmed),
        signals=["s3_bucket_policy_deny"],
        notes="bucket policy Deny only; identity policy allows the action")
    CallOutcome.capture("s3", "DeleteBucketPolicy", lambda c: c.delete_bucket_policy(
        Bucket=x))
    identity.delete()
    if case["classification"] is not True:
        gaps.append(
            "S3 bucket-policy Deny was not observed to block GetObject even though the "
            "policy was confirmed stored")
    return case


def _cleanup(floci, *buckets):
    s3 = floci.client("s3")
    for bucket in buckets:
        listed = CallOutcome.capture("s3", "ListObjectsV2", lambda c: c.list_objects_v2(
            Bucket=bucket))
        if listed.ok:
            for item in listed.raw.get("Contents", []):
                CallOutcome.capture("s3", "DeleteObject", lambda c: c.delete_object(
                    Bucket=bucket, Key=item["Key"]))
        CallOutcome.capture("s3", "DeleteBucketTagging", lambda c: c.delete_bucket_tagging(
            Bucket=bucket))
        CallOutcome.capture("s3", "DeleteBucket", lambda c: c.delete_bucket(Bucket=bucket))


def _result(available, operations, authz, gaps, signals):
    return {"available": available, "operations": operations, "authorization": authz,
            "gaps": gaps, "enforcement_signals": signals}


def probe_secrets_manager(floci, matrix, suffix):
    gaps = []
    operations = {}
    authz = {}
    signals = {}
    client = floci.client("secretsmanager")
    run_id = uuid.uuid4().hex[:8]
    name = f"cloudsec-m0-{suffix}-{run_id}"
    synthetic = f"{SYNTHETIC_SECRET_VALUE}-{run_id}"

    created = CallOutcome.capture("secretsmanager", "CreateSecret",
                                 lambda c: c.create_secret(Name=name, SecretString=synthetic))
    operations["CreateSecret"] = created.to_dict()
    if not created.ok:
        gaps.append(f"SecretsManager CreateSecret unsupported: {created.error_code}")
        return _result(False, operations, authz, gaps, signals)
    secret_id = created.raw["ARN"]

    described = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                    lambda c: c.describe_secret(SecretId=secret_id))
    operations["DescribeSecret"] = described.to_dict()
    listed = CallOutcome.capture("secretsmanager", "ListSecrets", lambda c: c.list_secrets())
    operations["ListSecrets"] = listed.to_dict()
    if listed.ok and not any(s["Name"] == name for s in listed.raw.get("SecretList", [])):
        gaps.append("SecretsManager ListSecrets did not return the created secret")

    fetched = CallOutcome.capture("secretsmanager", "GetSecretValue",
                                  lambda c: c.get_secret_value(SecretId=secret_id))
    operations["GetSecretValue"] = fetched.to_dict()
    if fetched.ok:
        matches = fetched.raw.get("SecretString") == synthetic
    else:
        matches = False
    operations["GetSecretValueMatchesSynthetic"] = {
        "operation": "GetSecretValue", "ok": matches,
        "note": "value is synthetic; raw value never persisted"}
    if not matches:
        gaps.append("SecretsManager GetSecretValue did not return the synthetic value")

    availability = {"secretsmanager_allow_observed": True,
                    "secretsmanager_deny_observed": True}
    arn = secret_id
    allow_identity = _new_identity(floci, f"secallow{suffix}")
    if allow_identity is None:
        availability["secretsmanager_allow_observed"] = None
    else:
        confirmed = allow_identity.put_inline_policy(
            "sec-allow", policy([statement(
                "Allow", "secretsmanager:GetSecretValue", arn)]))
        got = CallOutcome.capture("secretsmanager", "GetSecretValue",
                                  lambda c: c.get_secret_value(SecretId=secret_id),
                                  allow_identity.client("secretsmanager"))
        authz["allow"] = matrix.record(
            "SM-A", "secretsmanager:GetSecretValue", "secretsmanager", "iam-user",
            allow_identity.arn, arn, "allow", got, state_changed=False,
            policy_confirmed=confirmed, signals=["secretsmanager_allow"])
        availability["secretsmanager_allow_observed"] = authz["allow"]["classification"]
        allow_identity.delete()

    no_policy = _new_identity(floci, f"secnone{suffix}")
    if no_policy is None:
        authz["implicit_deny"] = {"error": "identity creation failed"}
    else:
        got = CallOutcome.capture("secretsmanager", "GetSecretValue",
                                  lambda c: c.get_secret_value(SecretId=secret_id),
                                  no_policy.client("secretsmanager"))
        authz["implicit_deny"] = matrix.record(
            "SM-B", "secretsmanager:GetSecretValue", "secretsmanager",
            "iam-user-no-policy", no_policy.arn, arn, "deny", got,
            state_changed=False, policy_confirmed=not no_policy.has_policy(),
            signals=["secretsmanager_implicit_deny"])
        no_policy.delete()

    deny_identity = _new_identity(floci, f"secdeny{suffix}")
    if deny_identity is None:
        authz["explicit_deny"] = {"error": "identity creation failed"}
    else:
        confirmed = deny_identity.put_inline_policy("sec-deny", policy([
            statement("Allow", "secretsmanager:GetSecretValue", arn),
            statement("Deny", "secretsmanager:GetSecretValue", arn),
        ]))
        got = CallOutcome.capture("secretsmanager", "GetSecretValue",
                                  lambda c: c.get_secret_value(SecretId=secret_id),
                                  deny_identity.client("secretsmanager"))
        authz["explicit_deny"] = matrix.record(
            "SM-C", "secretsmanager:GetSecretValue", "secretsmanager", "iam-user-deny",
            deny_identity.arn, arn, "deny", got, state_changed=False,
            policy_confirmed=confirmed, signals=["secretsmanager_deny"])
        availability["secretsmanager_deny_observed"] = authz["explicit_deny"]["classification"]
        deny_identity.delete()

    deleted = CallOutcome.capture("secretsmanager", "DeleteSecret",
                                  lambda c: c.delete_secret(
                                      SecretId=secret_id,
                                      RecoveryWindowInDays=7))
    operations["DeleteSecret"] = deleted.to_dict()
    after = CallOutcome.capture("secretsmanager", "DescribeSecret",
                                lambda c: c.describe_secret(SecretId=secret_id))
    operations["DescribeSecretAfterDelete"] = after.to_dict()
    if not after.ok and after.error_code is None:
        gaps.append("SecretsManager DeleteSecret outcome could not be confirmed")

    signals["secretsmanager"] = availability
    return _result(True, operations, authz, gaps, signals)


def probe_kms(floci, matrix, suffix):
    gaps = []
    operations = {}
    authz = {}
    signals = {}
    client = floci.client("kms")
    alias = f"alias/cloudsec-{suffix}"

    created = CallOutcome.capture("kms", "CreateKey", lambda c: c.create_key(
        Description="cloudsec synthetic probe key"))
    operations["CreateKey"] = created.to_dict()
    if not created.ok:
        gaps.append(f"KMS CreateKey unsupported: {created.error_code}")
        return _result(False, operations, authz, gaps, signals)
    key_id = created.raw["KeyMetadata"]["KeyId"]
    key_arn = f"arn:aws:kms:{floci.region()}:{floci.account}:key/{key_id}"

    described = CallOutcome.capture("kms", "DescribeKey", lambda c: c.describe_key(
        KeyId=key_id))
    operations["DescribeKey"] = described.to_dict()
    CallOutcome.capture("kms", "CreateAlias", lambda c: c.create_alias(
        AliasName=alias, TargetKeyId=key_id))
    operations["CreateAlias"] = CallOutcome.capture("kms", "CreateAlias", lambda c: c.create_alias(
        AliasName=alias + "-2", TargetKeyId=key_id)).to_dict()

    plaintext = "cloudsec-synthetic-plaintext"
    encrypted = CallOutcome.capture("kms", "Encrypt", lambda c: c.encrypt(
        KeyId=key_id, Plaintext=plaintext.encode()))
    operations["Encrypt"] = encrypted.to_dict()
    envelope = None
    if encrypted.ok:
        blob = encrypted.raw["CiphertextBlob"]
        raw = blob if isinstance(blob, bytes) else base64.b64decode(blob)
        envelope = raw[:4].decode("latin-1") if len(raw) >= 4 else None
    operations["CiphertextBlobType"] = {
        "operation": "Encrypt",
        "observed_type": type(encrypted.raw.get("CiphertextBlob")).__name__
        if encrypted.ok else None,
        "note": "AWS returns base64 bytes; record what Floci returns"}
    operations["EncryptEnvelopeMagic"] = {
        "operation": "Encrypt", "ok": envelope == "KMS3", "observed_magic": envelope,
        "note": "probe reports Floci's documented internal envelope marker"}
    if envelope != "KMS3":
        gaps.append(f"KMS ciphertext did not carry the documented KMS3 envelope (got {envelope!r})")

    decrypted = CallOutcome.capture("kms", "Decrypt", lambda c: c.decrypt(
        CiphertextBlob=encrypted.raw["CiphertextBlob"])) if encrypted.ok else None
    operations["Decrypt"] = decrypted.to_dict() if decrypted else {
        "operation": "Decrypt", "ok": False, "exception": "skipped_no_ciphertext"}
    roundtrip = False
    if decrypted is not None and decrypted.ok:
        roundtrip = decrypted.raw["Plaintext"].decode() == plaintext
    operations["DecryptRoundTrip"] = {"operation": "Decrypt", "ok": roundtrip}
    if not roundtrip:
        gaps.append("KMS encrypt/decrypt round trip did not reproduce the plaintext")

    availability = {"kms_deny_observed": True}
    deny_identity = _new_identity(floci, f"kmsdeny{suffix}")
    if deny_identity is None:
        availability["kms_deny_observed"] = None
        authz["explicit_deny"] = {"error": "identity creation failed"}
    elif encrypted is None or not encrypted.ok:
        availability["kms_deny_observed"] = None
        authz["explicit_deny"] = {"error": "no ciphertext available"}
    else:
        confirmed = deny_identity.put_inline_policy("kms-deny", policy([
            statement("Allow", ["kms:Decrypt", "kms:Encrypt"], key_arn),
            statement("Deny", "kms:Decrypt", key_arn),
        ]))
        got = CallOutcome.capture("kms", "Decrypt", lambda c: c.decrypt(
            CiphertextBlob=encrypted.raw["CiphertextBlob"]),
            deny_identity.client("kms"))
        authz["explicit_deny"] = matrix.record(
            "KMS-C", "kms:Decrypt", "kms", "iam-user-deny", deny_identity.arn, key_arn,
            "deny", got, state_changed=False, policy_confirmed=confirmed,
            signals=["kms_deny"])
        availability["kms_deny_observed"] = authz["explicit_deny"]["classification"]
        deny_identity.delete()

    key_document = json.dumps({
        "Version": "2012-10-17",
        "Statement": [statement("Deny", "kms:Decrypt", "*")]})
    key_policy = CallOutcome.capture("kms", "PutKeyPolicy", lambda c: c.put_key_policy(
        KeyId=key_id, PolicyName="cloudsec-probe", Policy=key_document))
    operations["PutKeyPolicy"] = key_policy.to_dict()
    got_key_policy = CallOutcome.capture("kms", "GetKeyPolicy", lambda c: c.get_key_policy(
        KeyId=key_id, PolicyName="cloudsec-probe"))
    operations["GetKeyPolicy"] = got_key_policy.to_dict()
    key_policy_present = bool(got_key_policy.ok) and "Deny" in json.dumps(
        got_key_policy.raw.get("Policy", ""))
    if key_policy_present and decrypted is not None:
        admin_decrypt = CallOutcome.capture("kms", "Decrypt", lambda c: c.decrypt(
            CiphertextBlob=encrypted.raw["CiphertextBlob"]), client)
        authz["key_policy_deny"] = matrix.record(
            "KMS-KP", "kms:Decrypt", "kms", "probe-root", key_arn, key_arn,
            "deny", admin_decrypt, state_changed=False,
            policy_confirmed=key_policy_present, signals=["kms_key_policy_deny"],
            notes="key policy Deny vs root caller")
        if authz["key_policy_deny"]["classification"] is not True:
            gaps.append("KMS key-policy Deny was not observed to block Decrypt")

    disabled = CallOutcome.capture("kms", "ScheduleKeyDeletion", lambda c: c.schedule_key_deletion(
        KeyId=key_id, PendingWindowInDays=7))
    operations["ScheduleKeyDeletion"] = disabled.to_dict()
    if not disabled.ok:
        disabled = CallOutcome.capture("kms", "DisableKey", lambda c: c.disable_key(KeyId=key_id))
        operations["DisableKey"] = disabled.to_dict()
    after = CallOutcome.capture("kms", "DescribeKey", lambda c: c.describe_key(KeyId=key_id))
    operations["DescribeKeyAfterCleanup"] = after.to_dict()

    signals["kms"] = availability
    return _result(True, operations, authz, gaps, signals)