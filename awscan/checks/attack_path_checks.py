def check_public_to_admin_exploit_path(session, network_module, ec2_module, iam_module):
    public_subnets = {
        subnet["SubnetId"]
        for subnet in network_module.describe_subnets(session)
        if subnet.get("MapPublicIpOnLaunch")
    }

    exposed_sg = set()
    for sg in ec2_module.list_security_groups(session):
        for perm in sg.get("IpPermissions", []):
            for ip in perm.get("IpRanges", []):
                if ip.get("CidrIp") != "0.0.0.0/0":
                    continue
                if perm.get("IpProtocol") == "-1":
                    exposed_sg.add(sg["GroupId"])
                    break
                if perm.get("FromPort") == 0 and perm.get("ToPort") == 65535:
                    exposed_sg.add(sg["GroupId"])
                    break

    risky_nodes = []
    for instance in ec2_module.describe_instances(session):
        instance_id = instance.get("InstanceId", "unknown-instance")
        subnet_id = instance.get("SubnetId")
        sg_ids = {sg.get("GroupId") for sg in instance.get("SecurityGroups", [])}
        profile_arn = instance.get("IamInstanceProfile", {}).get("Arn")

        if subnet_id not in public_subnets:
            continue
        if not sg_ids.intersection(exposed_sg):
            continue
        if not profile_arn:
            continue

        try:
            profile_roles = iam_module.get_instance_profile_roles(session, profile_arn)
        except Exception:
            continue

        for role in profile_roles:
            role_name = role.get("RoleName")
            if not role_name or iam_module.is_service_linked_role(role):
                continue
            if iam_module.role_has_admin_permissions(session, role_name):
                risky_nodes.append(
                    {
                        "instance_id": instance_id,
                        "subnet_id": subnet_id,
                        "security_groups": sorted(sg_ids.intersection(exposed_sg)),
                        "role_name": role_name,
                        "instance_profile_arn": profile_arn,
                    }
                )

    if risky_nodes:
        path_descriptions = []
        for node in risky_nodes:
            path_descriptions.append(
                f"{node['instance_id']} (subnet={node['subnet_id']}, sg={node['security_groups']}) "
                f"-> {node['instance_profile_arn']} -> role={node['role_name']}"
            )
        evidence = (
            "Detected concrete public-to-admin paths: " + "; ".join(path_descriptions)
        )
        return [{
            "type": "EXPLOIT_PATH_PUBLIC_TO_ADMIN",
            "resource": "account",
            "severity": "CRITICAL",
            "message": "Potential public-network-to-admin compromise chain detected",
            "evidence": evidence,
            "confidence": 0.92,
        }]

    return []
