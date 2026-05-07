from awscan.aws.session import get_client


def list_buckets(session):
    s3 = get_client(session, "s3")
    return s3.list_buckets()["Buckets"]


def is_bucket_public(session, bucket_name):
    s3 = get_client(session, "s3")
    evidence = []
    confidence = 0.55

    if _acl_allows_public_read_or_write(s3, bucket_name):
        evidence.append("ACL grants access to public group (AllUsers or AuthenticatedUsers).")
        confidence = max(confidence, 0.95)

    policy_status = _get_policy_public_status(s3, bucket_name)
    if policy_status is True:
        evidence.append("Bucket policy is public according to get_bucket_policy_status.")
        confidence = max(confidence, 0.9)

    block = _get_public_access_block_state(s3, bucket_name)
    if block and all(block.values()):
        if evidence:
            evidence.append(
                "Bucket-level Public Access Block is fully enabled; verify account-level and exceptions."
            )
            confidence = min(confidence, 0.7)
        return False, "Bucket-level Public Access Block is fully enabled.", 0.9

    if evidence:
        return True, " ".join(evidence), confidence

    return False, "No public ACL or public bucket policy signals were detected.", 0.9


def _acl_allows_public_read_or_write(s3_client, bucket_name):
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    except Exception:
        return False

    for grant in acl.get("Grants", []):
        grantee = str(grant.get("Grantee"))
        if "AllUsers" in grantee or "AuthenticatedUsers" in grantee:
            return True
    return False


def _get_policy_public_status(s3_client, bucket_name):
    try:
        status = s3_client.get_bucket_policy_status(Bucket=bucket_name)
    except Exception:
        return None
    return status.get("PolicyStatus", {}).get("IsPublic")


def _get_public_access_block_state(s3_client, bucket_name):
    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
    except Exception:
        return None

    config = response.get("PublicAccessBlockConfiguration", {})
    return {
        "BlockPublicAcls": bool(config.get("BlockPublicAcls")),
        "IgnorePublicAcls": bool(config.get("IgnorePublicAcls")),
        "BlockPublicPolicy": bool(config.get("BlockPublicPolicy")),
        "RestrictPublicBuckets": bool(config.get("RestrictPublicBuckets")),
    }
