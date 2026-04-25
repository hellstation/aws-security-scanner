def check_open_ports(session, ec2_module):
    results = []

    for sg in ec2_module.list_security_groups(session):
        for perm in sg.get("IpPermissions", []):

            from_port = perm.get("FromPort")
            to_port = perm.get("ToPort")
            protocol = perm.get("IpProtocol")

            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") == "0.0.0.0/0":

                    if protocol == "-1":
                        results.append({
                            "type": "SG_ALL_PROTOCOLS",
                            "resource": sg["GroupId"],
                            "severity": "CRITICAL",
                            "message": "All protocols open to the world"
                        })

                    if from_port == 0 and to_port == 65535:
                        results.append({
                            "type": "SG_ALL_PORTS",
                            "resource": sg["GroupId"],
                            "severity": "CRITICAL",
                            "message": "All ports open to the world"
                        })

    return results