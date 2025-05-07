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
