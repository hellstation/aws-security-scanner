def check_public_buckets(session, s3):
    results = []

    for b in s3.list_buckets(session):
        is_public, evidence, confidence = s3.is_bucket_public(session, b["Name"])
        if is_public:
            results.append({
                "type": "S3_PUBLIC",
                "resource": b["Name"],
                "severity": "HIGH",
                "message": "S3 bucket is public",
                "evidence": evidence,
                "confidence": confidence,
            })

    return results
