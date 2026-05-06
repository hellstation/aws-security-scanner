def check_imdsv2_required(session, ec2_module):
    results = []
    for instance in ec2_module.describe_instances(session):
        metadata = instance.get("MetadataOptions", {})
        tokens = metadata.get("HttpTokens", "optional")
        if tokens == "required":
            continue
        instance_id = instance.get("InstanceId", "unknown-instance")
        results.append({
            "type": "IMDSV2_NOT_REQUIRED",
            "resource": instance_id,
            "severity": "HIGH",
            "message": "EC2 instance does not require IMDSv2",
            "evidence": f"MetadataOptions.HttpTokens={tokens}",
        })
    return results
