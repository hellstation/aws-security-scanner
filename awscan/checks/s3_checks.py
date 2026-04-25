def check_public_buckets(session, s3):
    results = []

    for b in s3.list_buckets(session):
        if s3.is_bucket_public(session, b["Name"]):
            results.append({
                "type": "S3_PUBLIC",
                "resource": b["Name"],
                "severity": "HIGH",
                "message": "S3 bucket is public"
            })

    return results