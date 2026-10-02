import json

from ..authz import (Identity, assume_role, ensure_bucket, normalize_document,
                      policy, statement)
from ..result import CallOutcome

ROLE_SESSION_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [statement("Allow", "s3:GetObject", "*")]})
BUCKET = "cloudsec-sts-bucket"


def probe_iam(floci, suffix):
    gaps = []
    operations = {}
    label = f"iam{suffix}"
    iam = floci.client("iam")
    user = f"cloudsec-{label}-u"
    role = f"cloudsec-{label}-r"
    managed = f"cloudsec-{label}-managed"

    CallOutcome.capture("iam", "DeleteUser", lambda c: c.delete_user(UserName=user))
    created = CallOutcome.capture("iam", "CreateUser", lambda c: c.create_user(UserName=user))
    operations["CreateUser"] = created.to_dict()
    operations["GetUser"] = _capture(iam, "GetUser", lambda c: c.get_user(UserName=user))
    operations["ListUsers"] = _capture(iam, "ListUsers", lambda c: c.list_users())
    if not created.ok:
        gaps.append(f"IAM CreateUser unsupported: {created.error_code}")

    role_trust = policy([statement("Allow", "sts:AssumeRole", "*")])
    create_role = CallOutcome.capture("iam", "CreateRole", lambda c: c.create_role(
        RoleName=role, AssumeRolePolicyDocument=role_trust))
    operations["CreateRole"] = create_role.to_dict()
    operations["GetRole"] = _capture(iam, "GetRole", lambda c: c.get_role(RoleName=role))
    operations["ListRoles"] = _capture(iam, "ListRoles", lambda c: c.list_roles())

    key = CallOutcome.capture("iam", "CreateAccessKey", lambda c: c.create_access_key(
        UserName=user))
    operations["CreateAccessKey"] = _mask_key(key)
    operations["ListAccessKeys"] = _capture(iam, "ListAccessKeys",
                                            lambda c: c.list_access_keys(UserName=user))
    access_key_id = key.raw["AccessKey"]["AccessKeyId"] if key.ok else None

    deny_doc = policy([statement("Deny", "s3:*", "*")])
    put_inline = CallOutcome.capture("iam", "PutUserPolicy", lambda c: c.put_user_policy(
        UserName=user, PolicyName="cloudsec-deny", PolicyDocument=deny_doc))
    operations["PutUserPolicy"] = put_inline.to_dict()
    get_inline = CallOutcome.capture("iam", "GetUserPolicy", lambda c: c.get_user_policy(
        UserName=user, PolicyName="cloudsec-deny"))
    operations["GetUserPolicy"] = get_inline.to_dict()
    inline_roundtrip = None
    if get_inline.ok:
        stored = normalize_document(get_inline.raw.get("PolicyDocument"))
        inline_roundtrip = (isinstance(stored, dict)
                            and stored.get("Statement") == json.loads(deny_doc)["Statement"])
    operations["InlinePolicyPersisted"] = {"operation": "GetUserPolicy",
                                           "ok": bool(inline_roundtrip)}
    operations["InlinePolicyDocumentShape"] = {
        "operation": "GetUserPolicy",
        "observed_type": type(get_inline.raw.get("PolicyDocument")).__name__
        if get_inline.ok else None,
        "note": "AWS returns a URL-encoded string; record what Floci returns"}
    if inline_roundtrip is False:
        gaps.append("IAM inline policy did not round-trip with the submitted statements")
    operations["ListUserPolicies"] = _capture(iam, "ListUserPolicies",
                                              lambda c: c.list_user_policies(UserName=user))

    scoped = policy([statement("Allow", "s3:GetObject",
                               f"arn:aws:s3:::{BUCKET}/allowed/*")])
    operations["PutUserPolicyScoped"] = _capture(iam, "PutUserPolicy",
                                                 lambda c: c.put_user_policy(
                                                     UserName=user,
                                                     PolicyName="cloudsec-scoped",
                                                     PolicyDocument=scoped))
    operations["GetUserPolicyScoped"] = _capture(iam, "GetUserPolicy",
                                                 lambda c: c.get_user_policy(
                                                     UserName=user,
                                                     PolicyName="cloudsec-scoped"))

    arn = f"arn:aws:iam::{floci.account}:policy/{managed}"
    create_policy = CallOutcome.capture("iam", "CreatePolicy", lambda c: c.create_policy(
        PolicyName=managed, PolicyDocument=policy([statement("Allow", "iam:ListUsers", "*")])))
    operations["CreatePolicy"] = create_policy.to_dict()
    operations["GetPolicy"] = _capture(iam, "GetPolicy", lambda c: c.get_policy(PolicyArn=arn))
    attach = CallOutcome.capture("iam", "AttachUserPolicy", lambda c: c.attach_user_policy(
        UserName=user, PolicyArn=arn))
    operations["AttachUserPolicy"] = attach.to_dict()
    attached = _outcome(iam, "ListAttachedUserPolicies",
                        lambda c: c.list_attached_user_policies(UserName=user))
    operations["ListAttachedUserPolicies"] = attached.to_dict()
    managed_present = bool(attached.ok) and any(
        entry["PolicyArn"] == arn for entry in attached.raw.get("AttachedPolicies", []))
    operations["ManagedPolicyAttached"] = {"operation": "ListAttachedUserPolicies",
                                           "ok": managed_present}
    detach = CallOutcome.capture("iam", "DetachUserPolicy", lambda c: c.detach_user_policy(
        UserName=user, PolicyArn=arn))
    operations["DetachUserPolicy"] = detach.to_dict()
    after_detach = _outcome(iam, "ListAttachedUserPolicies",
                            lambda c: c.list_attached_user_policies(UserName=user))
    operations["DetachedPolicyGone"] = {
        "operation": "ListAttachedUserPolicies",
        "ok": bool(after_detach.ok) and not any(
            entry["PolicyArn"] == arn for entry in after_detach.raw.get("AttachedPolicies", []))}
    operations["DeletePolicy"] = _capture(iam, "DeletePolicy",
                                          lambda c: c.delete_policy(PolicyArn=arn))

    if access_key_id:
        CallOutcome.capture("iam", "DeleteAccessKey", lambda c: c.delete_access_key(
            UserName=user, AccessKeyId=access_key_id))
    for name in ("cloudsec-deny", "cloudsec-scoped"):
        CallOutcome.capture("iam", "DeleteUserPolicy", lambda c: c.delete_user_policy(
            UserName=user, PolicyName=name))
    CallOutcome.capture("iam", "DeleteUser", lambda c: c.delete_user(UserName=user))
    CallOutcome.capture("iam", "DeleteRole", lambda c: c.delete_role(RoleName=role))
    return {"available": not gaps, "operations": operations, "authorization": {},
            "gaps": gaps, "enforcement_signals": {}}


def _mask_key(outcome):
    data = outcome.to_dict()
    if data.get("ok"):
        data["result_summary"] = {"AccessKey": "created, value withheld"}
    return data


def _outcome(client, operation, func):
    return CallOutcome.capture(client.meta.service_model.service_name, operation, func,
                               client)


def _capture(client, operation, func):
    return _outcome(client, operation, func).to_dict()


def probe_sts(floci, matrix, suffix):
    gaps = []
    operations = {}
    authz = {}
    sts = floci.client("sts")
    bucket = f"{BUCKET}-{suffix}"
    bootstrap = Identity(floci, f"stsboot{suffix}")
    bootstrap_ready = bootstrap.create() and bootstrap.put_inline_policy(
        "sts-assume", policy([
            statement("Allow", "sts:AssumeRole", "*"),
            statement("Allow", ["s3:GetObject", "s3:PutObject", "s3:ListAllMyBuckets"],
                      "*"),
        ]))
    if not bootstrap_ready:
        gaps.append("could not create a Floci-issued principal permitted to AssumeRole")
    caller = bootstrap.client("sts") if bootstrap_ready else sts

    identity = CallOutcome.capture("sts", "GetCallerIdentity",
                                   lambda c: c.get_caller_identity(), sts)
    operations["GetCallerIdentity"] = identity.to_dict()
    if identity.ok:
        operations["GetCallerIdentityArn"] = identity.raw.get("Arn")
        operations["GetCallerIdentityAccount"] = identity.raw.get("Account")
    missing_role = CallOutcome.capture("sts", "AssumeRole", lambda c: c.assume_role(
        RoleArn=f"arn:aws:iam::{floci.account}:role/cloudsec-does-not-exist-{suffix}",
        RoleSessionName="missing"))
    operations["AssumeRoleMissingRole"] = missing_role.to_dict()
    if not missing_role.ok:
        operations["AssumeRoleMissingRoleObserved"] = missing_role.error_code
    else:
        gaps.append(
            "STS AssumeRole succeeded for a role ARN that was never created; Floci "
            "minted credentials for it")

    allowed_role = _role(floci, f"cloudsec-stsok-{suffix}",
                         policy([statement("Allow", ["s3:GetObject", "s3:ListAllMyBuckets"],
                                           "*")]))
    creds, assume_ok = assume_role(floci, allowed_role, f"ok{suffix}",
                                   duration_seconds=3600, caller=caller)
    operations["AssumeRole"] = assume_ok.to_dict()
    session_meta = None
    if creds is None:
        gaps.append(
            f"STS AssumeRole failed for an existing role ({assume_ok.error_code}). "
            f"The calling Floci-issued principal carried an inline policy allowing "
            f"sts:AssumeRole on Resource '*' and the role trusts '*'; no role could "
            f"be assumed, so the assumed-role matrix is inconclusive here")
    else:
        session_meta = {
            "expiration": creds["expiration"],
            "assumed_role_arn": creds["assumed_role_arn"],
            "packed_policy_size": creds["packed_policy_size"],
            "session_token_returned": bool(creds["session_token"]),
            "note": "expiry recorded from the response; probe does not wait for expiry"}
        operations["AssumeRoleSession"] = session_meta
        s3 = floci.client("s3", akid=creds["access_key_id"],
                          secret=creds["secret_access_key"],
                          token=creds["session_token"])
        temp_sts = floci.client("sts", akid=creds["access_key_id"],
                                secret=creds["secret_access_key"],
                                token=creds["session_token"])
        derived = CallOutcome.capture("sts", "GetCallerIdentity",
                                      lambda c: c.get_caller_identity(), temp_sts)
        operations["GetCallerIdentityWithTempCreds"] = derived.to_dict()
        operations["TempCredsCallerArn"] = derived.raw.get("Arn") if derived.ok else None
        operations["TempCredsMatchAssumedRole"] = bool(
            derived.ok and creds["assumed_role_arn"] and
            derived.raw.get("Arn") == creds["assumed_role_arn"])
        operations["TempCredsArnVsAssumeRoleArn"] = {
            "get_caller_identity": operations["TempCredsCallerArn"],
            "assume_role": creds["assumed_role_arn"]}
        if not operations["TempCredsMatchAssumedRole"]:
            gaps.append(
                "GetCallerIdentity under assumed-role credentials reported "
                f"{operations['TempCredsCallerArn']!r} rather than the ARN returned by "
                f"AssumeRole ({creds['assumed_role_arn']!r})")

    ensure_bucket(floci.client("s3"), bucket)
    floci.client("s3").put_object(Bucket=bucket, Key="ok.txt", Body=b"synthetic")

    if creds is not None:
        s3 = floci.client("s3", akid=creds["access_key_id"],
                          secret=creds["secret_access_key"],
                          token=creds["session_token"])
        allowed = _read(s3, bucket)
        authz["role_allow"] = matrix.record(
            "F-allow", "s3:GetObject", "s3", "assumed-role", allowed_role,
            f"arn:aws:s3:::{bucket}/ok.txt", "allow", allowed, state_changed=False,
            policy_confirmed=_role_policy_present(floci, allowed_role),
            signals=["sts_role_restrictions"],
            notes="role grants s3:GetObject; credentials obtained via AssumeRole")
        operations["TempCredsGetObject"] = allowed.to_dict()

    scoped_role = _role(floci, f"cloudsec-stsscope-{suffix}",
                        policy([statement("Allow", "s3:GetObject",
                                          f"arn:aws:s3:::{bucket}/*")]))
    scoped_creds, scoped_outcome = assume_role(floci, scoped_role, f"scope{suffix}",
                                               caller=caller)
    if scoped_creds is None:
        authz["role_scoped"] = {"assume_role": scoped_outcome.to_dict()}
        gaps.append("STS AssumeRole failed for the resource-scoped role")
    else:
        client = floci.client("s3", akid=scoped_creds["access_key_id"],
                              secret=scoped_creds["secret_access_key"],
                              token=scoped_creds["session_token"])
        other = f"{BUCKET}-other-{suffix}"
        ensure_bucket(floci.client("s3"), other)
        floci.client("s3").put_object(Bucket=other, Key="ok.txt", Body=b"synthetic")
        in_scope = _read(client, bucket)
        out_scope = _read(client, other)
        matrix.record("F-scope-x", "s3:GetObject", "s3", "assumed-role-scoped",
                      scoped_role, f"arn:aws:s3:::{bucket}/ok.txt", "allow", in_scope,
                      state_changed=False, policy_confirmed=True,
                      signals=["sts_role_scoping"], notes="in-scope bucket")
        case_out = matrix.record("F-scope-y", "s3:GetObject", "s3", "assumed-role-scoped",
                                 scoped_role, f"arn:aws:s3:::{other}/ok.txt", "deny",
                                 out_scope, state_changed=False, policy_confirmed=True,
                                 signals=["sts_role_scoping"], notes="out-of-scope bucket")
        authz["role_scoped"] = {"in_scope": in_scope.to_dict(), "out_of_scope": case_out}
        operations["TempCredsScopedOutOfScope"] = case_out
        CallOutcome.capture("s3", "DeleteObject", lambda c: floci.client("s3").delete_object(
            Bucket=other, Key="ok.txt"))
        CallOutcome.capture("s3", "DeleteBucket",
                            lambda c: floci.client("s3").delete_bucket(Bucket=other))

    deny_role = _role(floci, f"cloudsec-stsdeny-{suffix}", policy([
        statement("Allow", "s3:*", "*"),
        statement("Deny", "s3:GetObject", "*"),
    ]))
    deny_creds, deny_outcome = assume_role(floci, deny_role, f"deny{suffix}",
                                           caller=caller)
    if deny_creds is None:
        authz["role_explicit_deny"] = {"assume_role": deny_outcome.to_dict()}
        gaps.append("STS AssumeRole failed for the explicitly-denied role")
    else:
        client = floci.client("s3", akid=deny_creds["access_key_id"],
                              secret=deny_creds["secret_access_key"],
                              token=deny_creds["session_token"])
        denied = _read(client, bucket)
        case = matrix.record(
            "F-deny", "s3:GetObject", "s3", "assumed-role-deny", deny_role,
            f"arn:aws:s3:::{bucket}/ok.txt", "deny", denied, state_changed=False,
            policy_confirmed=_role_policy_present(floci, deny_role),
            signals=["sts_role_restrictions"],
            notes="explicit Deny on the role, exercised with temporary credentials")
        authz["role_explicit_deny"] = case
        operations["TempCredsExplicitDeny"] = denied.to_dict()

    trust_role = _role(floci, f"cloudsec-trust-{suffix}", None)
    outsider = Identity(floci, f"trust{suffix}")
    if outsider.create():
        allowed_assume = CallOutcome.capture("sts", "AssumeRole", lambda c: c.assume_role(
            RoleArn=trust_role, RoleSessionName="outsider"),
            outsider.client("sts"))
        authz["trust_permissive"] = matrix.record(
            "T-A", "sts:AssumeRole", "sts", "iam-user", outsider.arn, trust_role,
            "allow", allowed_assume, state_changed=False, policy_confirmed=True,
            notes="role trusts '*'; this user is outside the intended principal set")
        outsider.delete()

    restricted_trust = f"cloudsec-trustonly-{suffix}"
    role = _role(floci, restricted_trust, policy([statement("Allow", "s3:GetObject", "*")]),
                 trust_principal=policy([statement(
                     "Allow", "sts:AssumeRole",
                     f"arn:aws:iam::{floci.account}:user/cloudsec-trust-{suffix}")]))
    outside_user = Identity(floci, f"outsider{suffix}")
    if outside_user.create() and role:
        refused = CallOutcome.capture("sts", "AssumeRole", lambda c: c.assume_role(
            RoleArn=role, RoleSessionName="nottrusted"),
            outside_user.client("sts"))
        authz["trust_restricted"] = matrix.record(
            "T-B", "sts:AssumeRole", "sts", "iam-user-not-in-trust", outside_user.arn, role,
            "deny", refused, state_changed=False, policy_confirmed=True,
            signals=["sts_trust_enforcement"],
            notes="trust policy names a different user")
        outside_user.delete()
    else:
        authz["trust_restricted"] = {"error": "principal or role creation failed"}

    if bootstrap_ready:
        bootstrap.delete()
    for name in (f"cloudsec-stsok-{suffix}", f"cloudsec-stsscope-{suffix}",
                 f"cloudsec-stsdeny-{suffix}", f"cloudsec-trust-{suffix}",
                 restricted_trust):
        CallOutcome.capture("iam", "DeleteRolePolicy", lambda c: c.delete_role_policy(
            RoleName=name, PolicyName="probe"))
        CallOutcome.capture("iam", "DeleteRole", lambda c: c.delete_role(RoleName=name))

    for bucket_to_clear in (bucket,):
        CallOutcome.capture("s3", "DeleteObject",
                            lambda c: floci.client("s3").delete_object(
                                Bucket=bucket_to_clear, Key="ok.txt"))
        CallOutcome.capture("s3", "DeleteBucket",
                            lambda c: floci.client("s3").delete_bucket(
                                Bucket=bucket_to_clear))

    return {"available": True, "operations": operations, "authorization": authz,
            "gaps": gaps, "enforcement_signals": {}}


def _read(s3, bucket, key="ok.txt"):
    def call(client):
        client.get_object(Bucket=bucket, Key=key)["Body"].read()
        return {"Body": "read"}
    return CallOutcome.capture("s3", "GetObject", call, s3)


def _role(floci, name, document, trust_principal=None):
    iam = floci.client("iam")
    trust = trust_principal or policy([statement("Allow", "sts:AssumeRole", "*")])
    CallOutcome.capture("iam", "DeleteRolePolicy", lambda c: c.delete_role_policy(
        RoleName=name, PolicyName="probe"))
    CallOutcome.capture("iam", "DeleteRole", lambda c: c.delete_role(RoleName=name))
    created = CallOutcome.capture("iam", "CreateRole", lambda c: c.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust))
    if not created.ok:
        return None
    if document is not None:
        CallOutcome.capture("iam", "PutRolePolicy", lambda c: c.put_role_policy(
            RoleName=name, PolicyName="probe", PolicyDocument=document))
    return f"arn:aws:iam::{floci.account}:role/{name}"


def _role_policy_present(floci, role_arn):
    role_name = role_arn.rsplit("/", 1)[-1]
    got = CallOutcome.capture("iam", "GetRolePolicy", lambda c: c.get_role_policy(
        RoleName=role_name, PolicyName="probe"))
    return bool(got.ok)


def probe_unknown_credentials(floci, suffix):
    observations = {}
    gaps = []
    cases = [
        ("test_test_sts", "sts", "test", "test", None, "GetCallerIdentity"),
        ("test_test_s3", "s3", "test", "test", None, "ListBuckets"),
        ("unregistered_akid_sts", "sts", "AKIACLOUDSECUNKNOWN0001", "synthetic", None,
         "GetCallerIdentity"),
        ("unregistered_akid_s3", "s3", "AKIACLOUDSECUNKNOWN0002", "synthetic", None,
         "ListBuckets"),
        ("unregistered_akid_iam", "iam", "AKIACLOUDSECUNKNOWN0003", "synthetic", None,
         "ListUsers"),
    ]
    for name, service, akid, secret, token, operation in cases:
        client = floci.client(service, akid=akid, secret=secret, token=token)
        method = _snake(operation)
        outcome = CallOutcome.capture(service, operation,
                                      lambda c, m=method: getattr(c, m)(), client)
        observations[name] = outcome.to_dict()
        if outcome.ok and name.startswith("unregistered"):
            gaps.append(
                f"an unregistered access key was accepted for {operation} "
                f"({outcome.status}); Floci performed no credential validation")
    return {"available": True, "operations": {}, "authorization": {},
            "observations": observations, "gaps": gaps, "enforcement_signals": {}}


def _snake(name):
    out = []
    for index, char in enumerate(name):
        if char.isupper() and index:
            out.append("_")
        out.append(char.lower())
    return "".join(out)