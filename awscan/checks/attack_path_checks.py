def check_public_to_admin_exploit_path(session, network_module, ec2_module, iam_module):
    public_subnets = [
        subnet["SubnetId"]
        for subnet in network_module.describe_subnets(session)
        if subnet.get("MapPublicIpOnLaunch")
    ]

    exposed_sg = []
    for sg in ec2_module.list_security_groups(session):
        for perm in sg.get("IpPermissions", []):
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") != "0.0.0.0/0":
                    continue
                if perm.get("IpProtocol") == "-1":
                    exposed_sg.append(sg["GroupId"])
                    break
                if perm.get("FromPort") == 0 and perm.get("ToPort") == 65535:
                    exposed_sg.append(sg["GroupId"])
                    break

    admin_roles = []
    for role in iam_module.list_roles(session):
        if iam_module.is_service_linked_role(role):
            continue
        role_name = role["RoleName"]
        if iam_module.role_has_admin_permissions(session, role_name):
            admin_roles.append(role_name)

    if public_subnets and exposed_sg and admin_roles:
        evidence = (
            f"Public subnets: {public_subnets}; "
            f"Internet-exposed SGs: {sorted(set(exposed_sg))}; "
            f"Admin roles: {admin_roles}"
        )
        return [{
            "type": "EXPLOIT_PATH_PUBLIC_TO_ADMIN",
            "resource": "account",
            "severity": "CRITICAL",
            "message": "Potential public-network-to-admin compromise chain detected",
            "evidence": evidence,
        }]

    return []
