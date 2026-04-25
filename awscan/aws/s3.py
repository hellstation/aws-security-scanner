from awscan.aws.session import get_client


def list_buckets(session):
    s3 = get_client(session, "s3")
    return s3.list_buckets()["Buckets"]


def is_bucket_public(session, bucket_name):
    s3 = get_client(session, "s3")

    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl["Grants"]:
            if "AllUsers" in str(grant.get("Grantee")):
                return True
    except Exception:
        pass

    return False
