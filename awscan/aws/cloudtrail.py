from awscan.aws.session import get_client


def describe_trails(session):
    cloudtrail = get_client(session, "cloudtrail")
    return cloudtrail.describe_trails(includeShadowTrails=False).get("trailList", [])
