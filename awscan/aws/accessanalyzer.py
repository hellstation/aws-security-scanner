from awscan.aws.session import get_client


def list_analyzers(session):
    analyzer = get_client(session, "accessanalyzer")
    return analyzer.list_analyzers().get("analyzers", [])
