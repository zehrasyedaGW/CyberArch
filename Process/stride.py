import json
import argparse
import os
from collections import defaultdict

# --- STRIDE Categories ---
STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege"
}

# --- Threat Definitions ---
# Structure: { ResourceType: [ { check_function: function, threat_info: { description: str, stride: list[str], mitigation: str } } ] }
THREAT_RULES = defaultdict(list)

# --- Helper Functions ---

def is_cidr_open(cidr):
    """Checks if a CIDR block is wide open (0.0.0.0/0)."""
    return cidr == "0.0.0.0/0"

def is_port_sensitive(port):
    """Checks if a port is commonly considered sensitive (e.g., SSH, RDP)."""
    sensitive_ports = [22, 3389] # Add more as needed (e.g., DB ports)
    return port in sensitive_ports

def resolve_value(value, parameters, mappings):
    """
    Attempts to resolve CloudFormation intrinsic functions or references.
    Handles Ref and basic Fn::FindInMap.
    NOTE: This is a simplified resolver and won't handle complex nested functions.
    """
    if isinstance(value, dict):
        if "Ref" in value:
            ref_key = value["Ref"]
            # Check Parameters first
            if ref_key in parameters:
                # Use Default value if available, otherwise keep as Ref
                return parameters[ref_key].get("Default", f"Ref({ref_key})")
            else:
                # Could be a resource reference, keep as is for now
                return f"Ref({ref_key})"
        elif "Fn::FindInMap" in value:
            try:
                map_name, top_level_key, second_level_key = value["Fn::FindInMap"]
                # Resolve keys if they are Refs
                resolved_top_key = resolve_value(top_level_key, parameters, mappings)
                resolved_second_key = resolve_value(second_level_key, parameters, mappings)
                return mappings.get(map_name, {}).get(resolved_top_key, {}).get(resolved_second_key, f"Fn::FindInMap({value['Fn::FindInMap']})")
            except Exception:
                 # Fallback if resolution fails
                return f"Fn::FindInMap({value.get('Fn::FindInMap', 'Error')})"
        elif "Fn::GetAtt" in value:
             # Cannot resolve GetAtt easily without deployment context
            return f"Fn::GetAtt({value['Fn::GetAtt']})"
        elif "Fn::Join" in value:
            # Cannot resolve Join easily without deployment context
             return f"Fn::Join({value['Fn::Join']})"
        else:
            # Return complex dicts as string for now
            return str(value)
    return value # Return primitive types directly

# --- Check Functions for Resources ---

def check_security_group_ingress(resource_name, properties, parameters, mappings):
    """Checks Security Group Ingress rules for potential threats."""
    threats = []
    sg_ingress = properties.get("SecurityGroupIngress", [])
    if not isinstance(sg_ingress, list): sg_ingress = [] # Handle case where it might not be a list

    for rule in sg_ingress:
        cidr_ip = resolve_value(rule.get("CidrIp"), parameters, mappings)
        from_port = resolve_value(rule.get("FromPort"), parameters, mappings)
        to_port = resolve_value(rule.get("ToPort"), parameters, mappings)
        ip_protocol = resolve_value(rule.get("IpProtocol"), parameters, mappings)

        try:
            from_port_int = int(from_port) if str(from_port).isdigit() else None
            to_port_int = int(to_port) if str(to_port).isdigit() else None
        except (ValueError, TypeError):
            from_port_int = None
            to_port_int = None

        ports_str = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
        protocol_str = ip_protocol if ip_protocol != "-1" else "any"

        if cidr_ip and is_cidr_open(cidr_ip):
            threat_info = {
                "description": f"Ingress rule allows traffic from anywhere ({cidr_ip}) on port(s) {ports_str} (Protocol: {protocol_str}).",
                "stride": ["I", "S", "D"],
                "mitigation": "Restrict the CIDR range to known IPs or specific Security Groups. Avoid using 0.0.0.0/0 if possible, especially for sensitive ports."
            }
            threats.append(threat_info)

            if from_port_int is not None and to_port_int is not None:
                 # Check range or single port
                if from_port_int <= 22 <= to_port_int and is_port_sensitive(22):
                     threat_info_ssh = {
                        "description": f"SSH Port (22) appears open to the internet ({cidr_ip}).",
                        "stride": ["S", "E", "I"],
                        "mitigation": "Strongly recommend restricting SSH access to specific bastion host IPs or known administrative networks. Use VPNs or Session Manager instead of direct SSH exposure."
                     }
                     threats.append(threat_info_ssh)
                # Add checks for other sensitive ports (e.g., 3389 for RDP) if needed

        elif str(cidr_ip).startswith("Ref("):
             threat_info = {
                "description": f"Ingress rule references another resource/parameter ({cidr_ip}) for source on port(s) {ports_str} (Protocol: {protocol_str}).",
                "stride": ["I", "S"], # Potential info disclosure if referenced SG is too broad
                "mitigation": f"Verify the configuration of the referenced source ({cidr_ip}) to ensure it follows the principle of least privilege."
            }
             threats.append(threat_info)

    return threats

THREAT_RULES["AWS::EC2::SecurityGroup"].append({
    "check_function": check_security_group_ingress,
})


def check_nacl_entry(resource_name, properties, parameters, mappings):
    """Checks Network ACL entries for potential threats."""
    threats = []
    cidr_block = resolve_value(properties.get("CidrBlock"), parameters, mappings)
    egress = properties.get("Egress", "false") # Default is ingress
    rule_action = properties.get("RuleAction", "allow")
    port_range = properties.get("PortRange", {})
    from_port = resolve_value(port_range.get("From"), parameters, mappings)
    to_port = resolve_value(port_range.get("To"), parameters, mappings)
    protocol = resolve_value(properties.get("Protocol"), parameters, mappings) # -1 means all

    direction = "Egress" if egress == "true" else "Ingress"
    ports_str = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
    protocol_str = protocol if protocol != "-1" else "any"


    if rule_action == "allow" and cidr_block and is_cidr_open(cidr_block):
        threat_info = {
            "description": f"NACL {direction} rule allows traffic from/to anywhere ({cidr_block}) on port(s) {ports_str} (Protocol: {protocol_str}).",
            "stride": ["I", "D"], # NACLs are stateless, broad allow rules can be risky
            "mitigation": "Review NACL rules for necessity. While NACLs are often broader than Security Groups, ensure 'allow all' rules are intentional and don't bypass Security Group controls unexpectedly."
        }
        threats.append(threat_info)
        # Could add specific port checks here too if desired
    elif str(cidr_block).startswith("Ref("):
         threat_info = {
            "description": f"NACL {direction} rule references another resource/parameter ({cidr_block}) for source/destination on port(s) {ports_str} (Protocol: {protocol_str}).",
            "stride": ["I"],
            "mitigation": f"Verify the configuration of the referenced source/destination ({cidr_block}) to ensure it aligns with network segmentation goals."
        }
         threats.append(threat_info)

    return threats

THREAT_RULES["AWS::EC2::NetworkAclEntry"].append({
    "check_function": check_nacl_entry,
})


def check_instance_exposure(resource_name, properties, parameters, mappings):
    """Checks if an EC2 instance might be overly exposed."""
    threats = []
    subnet_id = resolve_value(properties.get("SubnetId"), parameters, mappings)
    # Note: Determining if a subnet is public requires analyzing Route Tables,
    # which is complex without full context. This check is basic.
    # A more advanced check would trace the subnet's route table to an Internet Gateway.
    if "PublicSubnet" in str(subnet_id): # Basic check based on naming convention in the sample
         threat_info = {
            "description": f"Instance is potentially placed in a public subnet ({subnet_id}).",
            "stride": ["I", "S", "D", "T"],
            "mitigation": "Ensure instances are placed in private subnets unless they explicitly require direct internet exposure (e.g., NAT Instances, Bastion Hosts). Use Load Balancers for public access to applications."
        }
         threats.append(threat_info)

    # Check for public IP assignment (less common in modern templates with ELBs/NATs)
    map_public_ip = properties.get("NetworkInterfaces", [{}])[0].get("AssociatePublicIpAddress", "false")
    if str(map_public_ip).lower() == "true":
         threat_info = {
            "description": "Instance is configured to associate a public IP address directly.",
            "stride": ["I", "S", "D", "T"],
            "mitigation": "Avoid assigning public IPs directly to instances unless absolutely necessary (e.g., Bastion). Prefer private subnets and access via Load Balancers or NAT Gateways."
        }
         threats.append(threat_info)

    # Check for sensitive UserData (basic check for keywords)
    user_data = properties.get("UserData", "")
    if isinstance(user_data, dict) and "Fn::Base64" in user_data:
        # In a real scenario, you'd decode this, but for now, just check if it exists
        if any(keyword in str(user_data).lower() for keyword in ["password", "secret", "key", "token"]):
             threat_info = {
                "description": "Instance UserData might contain sensitive information (keywords found).",
                "stride": ["I", "E"],
                "mitigation": "Avoid embedding secrets directly in UserData. Use secrets management services (like AWS Secrets Manager or Parameter Store) and retrieve secrets at runtime via IAM roles."
            }
             threats.append(threat_info)

    return threats

THREAT_RULES["AWS::EC2::Instance"].append({
    "check_function": check_instance_exposure,
})
THREAT_RULES["AWS::AutoScaling::LaunchConfiguration"].append({ # Also check Launch Configs
    "check_function": check_instance_exposure, # Reuse the same checks
})


def check_elb_scheme(resource_name, properties, parameters, mappings):
    """Checks the scheme of an Elastic Load Balancer."""
    threats = []
    scheme = resolve_value(properties.get("Scheme"), parameters, mappings)
    # Default scheme is internet-facing if not specified
    if scheme is None or scheme == "internet-facing":
        threat_info = {
            "description": "Load Balancer is internet-facing.",
            "stride": ["D", "S", "I"], # Entry point for external threats
            "mitigation": "Ensure internet-facing ELBs are necessary. Consider using AWS WAF for protection. Ensure backend instances/security groups are appropriately secured."
        }
        threats.append(threat_info)
    elif scheme == "internal":
         threat_info = {
            "description": "Load Balancer is internal.",
            "stride": [], # Generally lower risk, but still a network component
            "mitigation": "Ensure Security Groups associated with the internal ELB and its targets restrict traffic appropriately within the VPC."
        }
         threats.append(threat_info)

    # Check for HTTP listeners (unencrypted traffic)
    listeners = properties.get("Listeners", [])
    if not isinstance(listeners, list): listeners = []
    for listener in listeners:
        protocol = resolve_value(listener.get("Protocol"), parameters, mappings)
        if str(protocol).upper() == "HTTP":
             threat_info = {
                "description": f"Load Balancer has an HTTP listener (Port: {listener.get('LoadBalancerPort', 'N/A')}). Traffic is unencrypted.",
                "stride": ["I", "T"],
                "mitigation": "Prefer HTTPS listeners for encrypted traffic. Use ACM to manage certificates. If HTTP is required, consider redirection to HTTPS."
            }
             threats.append(threat_info)

    return threats

THREAT_RULES["AWS::ElasticLoadBalancing::LoadBalancer"].append({
    "check_function": check_elb_scheme,
})
# Add checks for AWS::ElasticLoadBalancingV2::LoadBalancer (ALB/NLB) if needed


# --- Main Processing Function ---

def generate_threat_model(template_data):
    """Parses the template and generates threat information."""
    resources = template_data.get("Resources", {})
    parameters = template_data.get("Parameters", {})
    mappings = template_data.get("Mappings", {})
    identified_threats = defaultdict(list)

    if not resources:
        print("Warning: No 'Resources' section found in the template.")
        return identified_threats

    for resource_name, resource_details in resources.items():
        resource_type = resource_details.get("Type")
        properties = resource_details.get("Properties", {})

        if not resource_type or not properties:
            continue # Skip resources without Type or Properties

        # Apply rules for the specific resource type
        if resource_type in THREAT_RULES:
            for rule in THREAT_RULES[resource_type]:
                check_func = rule["check_function"]
                try:
                    threats_found = check_func(resource_name, properties, parameters, mappings)
                    if threats_found:
                        # Append the check function's specific threat info
                        for threat in threats_found:
                             identified_threats[resource_name].append({
                                 "resource_type": resource_type,
                                 **threat # Unpack description, stride, mitigation
                             })
                except Exception as e:
                    print(f"Error processing rule for {resource_name} ({resource_type}): {e}")


    return identified_threats

# --- Output Formatting ---

def format_markdown_report(threats):
    """Formats the identified threats into a Markdown report."""
    if not threats:
        return "# Threat Model Report\n\nNo potential threats identified by the automated scan.\n"

    md = ["# Threat Model Report\n"]
    md.append("This report outlines potential threats identified by an automated scan of the CloudFormation template. **Manual review is essential** to validate these findings and assess risks in the context of the specific application.\n")

    for resource_name, resource_threats in threats.items():
        if not resource_threats: continue

        resource_type = resource_threats[0]['resource_type'] # Get type from first threat
        md.append(f"## Resource: `{resource_name}` (`{resource_type}`)\n")

        for i, threat in enumerate(resource_threats):
            stride_categories = ", ".join([f"{s} ({STRIDE[s]})" for s in threat['stride']])
            md.append(f"### Threat {i+1}: {threat['description']}\n")
            md.append(f"- **STRIDE Categories:** {stride_categories}")
            md.append(f"- **Potential Mitigation / Area to Review:** {threat['mitigation']}\n")
        md.append("\n---\n") # Separator

    return "\n".join(md)

# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a basic threat model from an AWS CloudFormation template.")
    parser.add_argument("template_file", help="Path to the CloudFormation template file (JSON format).")
    parser.add_argument("-o", "--output", default="threat_model_report.md", help="Output Markdown file name (default: threat_model_report.md).")

    args = parser.parse_args()

    # Validate input file path
    if not os.path.isfile(args.template_file):
        print(f"Error: Template file not found at '{args.template_file}'")
        exit(1)

    # Read and parse the template
    try:
        with open(args.template_file, 'r') as f:
            template_content = f.read()
            # Basic check if it looks like JSON before parsing
            if not template_content.strip().startswith('{'):
                 print(f"Error: Input file '{args.template_file}' does not appear to be a valid JSON file.")
                 exit(1)
            cloudformation_template = json.loads(template_content)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON template file '{args.template_file}': {e}")
        exit(1)
    except Exception as e:
        print(f"Error reading file '{args.template_file}': {e}")
        exit(1)

    # Generate the threat model
    print(f"Analyzing template: {args.template_file}...")
    identified_threats = generate_threat_model(cloudformation_template)

    # Format and write the report
    markdown_report = format_markdown_report(identified_threats)
    try:
        with open(args.output, 'w') as f:
            f.write(markdown_report)
        print(f"Threat model report generated: {args.output}")
    except Exception as e:
        print(f"Error writing output file '{args.output}': {e}")
        exit(1)