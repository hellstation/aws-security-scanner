from awscan.aws.session import get_client


def list_analyzers(session):
    analyzer = get_client(session, "accessanalyzer")
    paginator = analyzer.get_paginator("list_analyzers")
    analyzers = []
    for page in paginator.paginate():
        analyzers.extend(page.get("analyzers", []))
    return analyzers
