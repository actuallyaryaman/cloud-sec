from . import compute, identity, observability, storage

probe_iam = identity.probe_iam
probe_sts = identity.probe_sts
probe_unknown_credentials = identity.probe_unknown_credentials
probe_s3 = storage.probe
probe_secrets_manager = storage.probe_secrets_manager
probe_kms = storage.probe_kms
probe_cloudwatch_logs = observability.probe_cloudwatch_logs
setup_cloudtrail = observability.setup_cloudtrail
perform_marked_actions = observability.perform_marked_actions
finalize_cloudtrail = observability.finalize_cloudtrail
probe_config = observability.probe_config
probe_lambda = compute.probe