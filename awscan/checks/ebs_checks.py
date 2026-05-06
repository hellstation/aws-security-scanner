def check_ebs_encryption(session, ec2_module):
    results = []
    for volume in ec2_module.describe_volumes(session):
        if volume.get("Encrypted"):
            continue
        volume_id = volume.get("VolumeId", "unknown-volume")
        results.append({
            "type": "EBS_UNENCRYPTED",
            "resource": volume_id,
            "severity": "HIGH",
            "message": "EBS volume is not encrypted at rest",
            "evidence": f"Encrypted={volume.get('Encrypted')}",
        })
    return results
