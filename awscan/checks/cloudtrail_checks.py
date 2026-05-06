def check_cloudtrail_enabled(session, cloudtrail_module):
    trails = cloudtrail_module.describe_trails(session)
    if trails:
        return []

    return [{
        "type": "CLOUDTRAIL_DISABLED",
        "resource": "account",
        "severity": "HIGH",
        "message": "No CloudTrail trail is configured",
        "evidence": "describe_trails returned an empty trailList.",
    }]
