import json
import os
import shutil
import re

# 1. Update daemon.json with hardening flags
def update_daemon_json(path="/etc/docker/daemon.json"):
    hardening_flags = {
        "icc": False,
        "userns-remap": "default",
        "no-new-privileges": True,
        "live-restore": True,
        "log-driver": "json-file",
        "log-opts": {
            "max-size": "10m",
            "max-file": "3"
        }
    }
    # Backup
    if os.path.exists(path):
        shutil.copy2(path, path + ".bak")
        with open(path, "r") as f:
            try:
                config = json.load(f)
            except Exception:
                config = {}
    else:
        config = {}

    config.update(hardening_flags)
    with open(path, "w") as f:
        json.dump(config, f, indent=2)
    print(f"Updated {path} with hardening flags.")

# 2. Inject USER, HEALTHCHECK, and limits into Dockerfile
def update_dockerfile(dockerfile_path="Dockerfile"):
    with open(dockerfile_path, "r") as f:
        lines = f.readlines()

    # Ensure USER is set (not root)
    user_present = any(line.strip().startswith("USER ") for line in lines)
    if not user_present:
        # Insert USER before CMD
        for i, line in enumerate(lines):
            if line.strip().startswith("CMD"):
                lines.insert(i, "USER appuser\n")
                break

    # Ensure HEALTHCHECK is present
    healthcheck_present = any(line.strip().startswith("HEALTHCHECK") for line in lines)
    if not healthcheck_present:
        # Insert HEALTHCHECK before CMD
        for i, line in enumerate(lines):
            if line.strip().startswith("CMD"):
                lines.insert(i, 'HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \\\n  CMD curl --fail http://localhost:5000/health || exit 1\n')
                break

    # Write back
    with open(dockerfile_path, "w") as f:
        f.writelines(lines)
    print(f"Checked/updated {dockerfile_path} for USER and HEALTHCHECK.")
# 3. Inject limits into docker-compose.yml
def update_docker_compose(compose_path="docker-compose.yml"):
    with open(compose_path, "r") as f:
        content = f.read()

    # Ensure read_only, security_opt, mem_limit, pids_limit, healthcheck for web and db
    def ensure_service_limits(service_name, content):
        # Add or update the relevant fields for the service
        pattern = rf"({service_name}:\n(?:[ \t]+.+\n)+)"
        match = re.search(pattern, content)
        if not match:
            return content  # Service not found

        service_block = match.group(1)
        # Add/replace fields
        for field, value in [
            ("read_only", "true"),
            ("security_opt", "- no-new-privileges:true"),
            ("mem_limit", "256m" if service_name == "web" else "512m"),
            ("pids_limit", "100"),
        ]:
            if field not in service_block:
                # Add after image/build/env_file
                insert_after = "env_file" if "env_file" in service_block else "image"
                pattern2 = rf"({insert_after}:[^\n]*\n)"
                service_block = re.sub(pattern2, rf"\1    {field}: {value}\n", service_block, count=1)
        # Add healthcheck if missing (for web)
        if service_name == "web" and "healthcheck:" not in service_block:
            healthcheck = (
                "    healthcheck:\n"
                "      test: [\"CMD\", \"curl\", \"--fail\", \"http://localhost:5000/health\"]\n"
                "      interval: 30s\n"
                "      timeout: 10s\n"
                "      retries: 3\n"
            )
            service_block += healthcheck
        # Replace in content
        content = content.replace(match.group(1), service_block)
        return content

    for service in ["web", "db"]:
        content = ensure_service_limits(service, content)

    with open(compose_path, "w") as f:
        f.write(content)
    print(f"Checked/updated {compose_path} for limits and security options.")

if __name__ == "__main__":
    # 1. Update daemon.json (requires sudo/root)
    try:
        update_daemon_json()
    except PermissionError:
        print("Permission denied: run this script with sudo to update /etc/docker/daemon.json.")

    # 2. Update Dockerfile
    update_dockerfile()

    # 3. Update docker-compose.yml
    update_docker_compose()