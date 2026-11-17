
def assess_device(device):
    """
    Assess a discovered device using observed network indicators.

    This is a preliminary security assessment, not a
    vulnerability scanner or proof of compromise.
    """

    risk_score = 0
    findings = []
    recommendations = []

    open_ports = device.get("open_ports", [])

    if 23 in open_ports:
        risk_score += 3
        findings.append(
            "Telnet service is accessible. Telnet does not encrypt network communication."
        )
        recommendations.append(
            "Disable Telnet and use secure remote administration such as SSH where appropriate."
        )

    if 445 in open_ports:
        risk_score += 2
        findings.append("SMB file-sharing service is accessible.")
        recommendations.append(
            "Check whether SMB sharing is required and restrict access to trusted devices."
        )

    if 554 in open_ports or 8554 in open_ports:
        risk_score += 2
        findings.append("RTSP media-streaming service is accessible.")
        recommendations.append(
            "Verify whether the service is required and ensure authentication is enabled."
        )

    if 8000 in open_ports or 8080 in open_ports:
        risk_score += 1
        findings.append("An alternative HTTP or management service is accessible.")
        recommendations.append(
            "Identify the service and ensure its management interface is protected."
        )

    if 3389 in open_ports:
        risk_score += 2
        findings.append("Remote Desktop service is accessible.")
        recommendations.append(
            "Restrict Remote Desktop access to trusted networks and authorized users."
        )

    if 5555 in open_ports:
        risk_score += 3
        findings.append("An Android Debug Bridge port is accessible.")
        recommendations.append(
            "Disable network ADB debugging when it is not required."
        )

    if 21 in open_ports:
        risk_score += 2
        findings.append("FTP service is accessible.")
        recommendations.append(
            "Prefer secure file transfer methods and disable unnecessary FTP access."
        )

    if risk_score >= 5:
        risk_level = "High"
    elif risk_score >= 2:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    if not findings:
        findings.append(
            "No specific security indicators were detected by the current assessment rules."
        )
        recommendations.append(
            "Keep device software updated and use strong passwords."
        )

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "findings": findings,
        "recommendations": recommendations
    }
