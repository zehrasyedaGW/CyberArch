# Threat Model Report

This report outlines potential threats identified by an automated scan of the CloudFormation template. **Manual review is essential** to validate these findings and assess risks in the context of the specific application.

## Resource: `MySecurityGroup` (`AWS::EC2::SecurityGroup`)

### Threat 1: Ingress rule allows traffic from anywhere (0.0.0.0/0) on port(s) 22 (Protocol: tcp).

- **STRIDE Categories:** I (Information Disclosure), S (Spoofing), D (Denial of Service)
- **Potential Mitigation / Area to Review:** Restrict the CIDR range to known IPs or specific Security Groups. Avoid using 0.0.0.0/0 if possible, especially for sensitive ports.

### Threat 2: SSH Port (22) appears open to the internet (0.0.0.0/0).

- **STRIDE Categories:** S (Spoofing), E (Elevation of Privilege), I (Information Disclosure)
- **Potential Mitigation / Area to Review:** Strongly recommend restricting SSH access to specific bastion host IPs or known administrative networks. Use VPNs or Session Manager instead of direct SSH exposure.

---

## MITRE ATT&CK for Containers - Relevant Techniques

| Threat | MITRE ATT&CK Technique | ID | Description |
|--------|-------------------------|----|-------------|
| Ingress rule allows traffic from anywhere (0.0.0.0/0) on port 22 | [External Remote Services](https://attack.mitre.org/techniques/T1133/) | T1133 | Adversaries may use exposed SSH ports to gain initial access. |
| SSH Port (22) appears open to the internet (0.0.0.0/0) | [Valid Accounts](https://attack.mitre.org/techniques/T1078/) | T1078 | Use of compromised SSH credentials to access exposed services. |
|  | [Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/) | T1068 | Gaining elevated access via vulnerabilities in exposed services. |
|  | [Access to Container](https://attack.mitre.org/techniques/T1611/) | T1611 | Direct access to container environment via exposed ports. |

---

## Mapping Vulnerabilities to NIST 800-53 Controls

| Threat | Vulnerability | NIST 800-53 Control(s) | Description |
|--------|---------------|------------------------|-------------|
| Ingress rule allows traffic from 0.0.0.0/0 on port 22 | Excessively broad network access | **AC-4**: Information Flow Enforcement<br>**SC-7**: Boundary Protection<br>**SC-7(5)**: Deny by default | Enforce flow restrictions and restrict access at the network boundary. |
| SSH Port open to the internet | Direct SSH exposure, risk of brute-force or credential theft | **AC-17**: Remote Access<br>**AC-17(2)**: Protection of Privileged Commands<br>**SC-12**: Cryptographic Key Establishment<br>**IA-2**: Identification and Authentication (Organizational Users) | Require secure remote access protocols, strong authentication, and restrict privileged access. |
