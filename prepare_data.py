#!/usr/bin/env python3
"""Prepare CVE-Bench task data from the cve-bench repository.

Clones uiuc-kang-lab/cve-bench, reads all metadata + eval.yml prompts,
classifies each CVE's infrastructure requirements, generates flattened
docker-compose files, and produces data/task_index.json.

Usage:
    python prepare_data.py [--cve-bench-dir PATH] [--output data/task_index.json]
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# CVE-Bench version tag (matches Docker Hub image tags)
# ---------------------------------------------------------------------------
CVEBENCH_TAG = "2.1.0"

# Keys hidden from the agent (stored server-side)
HIDDEN_KEYS = ["solution_script"]

# CVE → APPLICATION_NAME mapping (from docker-bake.hcl)
APPLICATION_NAMES = {
    "CVE-2023-37999": "wp_htmega",
    "CVE-2023-51483": "wordpress",
    "CVE-2024-2359": "lollms",
    "CVE-2024-2624": "lollms",
    "CVE-2024-2771": "wp_fluent_forms",
    "CVE-2024-3234": "default",
    "CVE-2024-3408": "default",
    "CVE-2024-3495": "wordpress",
    "CVE-2024-3552": "wordpress",
    "CVE-2024-4223": "wordpress",
    "CVE-2024-4320": "lollms",
    "CVE-2024-4323": "fluent_bit",
    "CVE-2024-4442": "wordpress",
    "CVE-2024-4443": "wordpress",
    "CVE-2024-4701": "genie",
    "CVE-2024-5084": "wordpress",
    "CVE-2024-5314": "dolibarr",
    "CVE-2024-5315": "dolibarr",
    "CVE-2024-5452": "lightning_ai",
    "CVE-2024-22120": "zabbix",
    "CVE-2024-25641": "cacti",
    "CVE-2024-30542": "wordpress",
    "CVE-2024-31611": "seacms",
    "CVE-2024-32167": "omos",
    "CVE-2024-32511": "wordpress",
    "CVE-2024-32964": "lobe_chat",
    "CVE-2024-32980": "default",
    "CVE-2024-32986": "pwas_firefox",
    "CVE-2024-34070": "froxlor",
    "CVE-2024-34340": "cacti",
    "CVE-2024-34359": "default",
    "CVE-2024-34716": "prestashop",
    "CVE-2024-35187": "stalwart",
    "CVE-2024-36412": "suitecrm",
    "CVE-2024-36675": "spage",
    "CVE-2024-36779": "stock",
    "CVE-2024-36858": "jan",
    "CVE-2024-37388": "ebookmeta",
    "CVE-2024-37831": "payroll",
    "CVE-2024-37849": "billing",
}


def read_file_safe(path: Path) -> str | None:
    """Read a text file, returning None if it doesn't exist."""
    if not path.exists() or not path.is_file():
        return None
    try:
        content = path.read_bytes()
        if b"\x00" in content[:8192]:
            return None
        return content.decode("utf-8", errors="replace")
    except Exception:
        return None


def parse_env_file(env_path: Path) -> dict[str, str]:
    """Parse a .env file into a dict."""
    env = {}
    content = read_file_safe(env_path)
    if not content:
        return env
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip()
    return env


def classify_cve(compose_content: str) -> dict:
    """Classify a CVE's infrastructure from its compose.yml content."""
    info = {
        "has_mariadb": False,
        "mariadb_version": None,
        "has_wordpress": False,
        "has_auxiliary_server": False,
        "auxiliary_server_image": None,
        "has_db_sql": False,
        "custom_target_env": {},
        "custom_target_depends": [],
        "custom_db_env": {},
        "custom_db_volumes": [],
        "custom_services": {},
    }

    if "compose-wp.yml" in compose_content:
        info["has_wordpress"] = True
        info["has_mariadb"] = True

    if "mariadb" in compose_content and "compose.yml" in compose_content:
        info["has_mariadb"] = True

    if "mariadb-11-8" in compose_content:
        info["mariadb_version"] = "11.8"
    elif "mariadb-10-6" in compose_content:
        info["mariadb_version"] = "10.6"

    # Detect auxiliary servers (Zabbix, Fluent Bit, etc.)
    # Look for service definitions that aren't target, db, or secrets_init
    service_pattern = re.compile(r"^\s{2}(\w[\w-]*):", re.MULTILINE)
    services = service_pattern.findall(compose_content)
    for svc in services:
        if svc not in ("target", "db", "include", "services"):
            if svc == "server":
                info["has_auxiliary_server"] = True

    return info


def build_task_index(cve_bench_dir: Path, output_dir: Path) -> list[dict]:
    """Walk cve-bench directory and build task index."""
    tasks: list[dict] = []

    challenges_dir = cve_bench_dir / "src" / "critical" / "challenges"
    metadata_dir = cve_bench_dir / "src" / "critical" / "metadata"

    if not challenges_dir.exists():
        print(f"ERROR: challenges directory not found: {challenges_dir}", file=sys.stderr)
        sys.exit(1)

    for cve_dir in sorted(challenges_dir.iterdir()):
        if not cve_dir.is_dir():
            continue

        cve_id = cve_dir.name
        cve_lower = cve_id.lower()
        print(f"  Processing {cve_id}...")

        # Read eval.yml for prompts
        eval_path = cve_dir / "eval.yml"
        eval_content = read_file_safe(eval_path)
        if not eval_content:
            print(f"    WARNING: no eval.yml, skipping")
            continue

        eval_data = yaml.safe_load(eval_content)
        variants = eval_data.get("variants", {})

        # Read metadata
        meta_path = metadata_dir / f"{cve_id}.yml"
        meta_content = read_file_safe(meta_path)
        if not meta_content:
            print(f"    WARNING: no metadata, skipping")
            continue
        metadata = yaml.safe_load(meta_content)

        # Read .env
        env_vars = parse_env_file(cve_dir / ".env")

        # Read compose.yml to classify infrastructure
        compose_content = read_file_safe(cve_dir / "compose.yml") or ""
        infra = classify_cve(compose_content)

        # Check for DB SQL
        db_sql_path = cve_dir / "db" / "db.sql"
        has_db_sql = db_sql_path.exists()

        # Read solution script (hidden from agent)
        solution_path = cve_dir / "solution" / "solution.sh"
        solution_script = read_file_safe(solution_path)

        # Determine DB type
        db_type = None
        mariadb_version = "11.8"
        if infra["has_mariadb"]:
            db_type = "mariadb"
            if infra["mariadb_version"]:
                mariadb_version = infra["mariadb_version"]

        # Application name
        app_name = APPLICATION_NAMES.get(cve_id, "default")

        # Copy per-CVE data to output directory
        cve_out_dir = output_dir / "challenges" / cve_lower
        cve_out_dir.mkdir(parents=True, exist_ok=True)

        # Copy metadata
        (cve_out_dir / "metadata.yml").write_text(meta_content)

        # Copy .env
        env_content = read_file_safe(cve_dir / ".env")
        if env_content:
            (cve_out_dir / ".env").write_text(env_content)

        # Copy DB SQL if present
        if has_db_sql:
            db_out_dir = cve_out_dir / "db"
            db_out_dir.mkdir(exist_ok=True)
            (db_out_dir / "db.sql").write_bytes(db_sql_path.read_bytes())

        # Copy original compose.yml (for reference)
        if compose_content:
            (cve_out_dir / "compose.original.yml").write_text(compose_content)

        # Generate flattened compose.yml
        flattened = generate_flattened_compose(
            cve_id=cve_id,
            cve_lower=cve_lower,
            db_type=db_type,
            mariadb_version=mariadb_version,
            has_wordpress=infra["has_wordpress"],
            has_db_sql=has_db_sql,
            has_auxiliary_server=infra["has_auxiliary_server"],
            env_vars=env_vars,
            compose_content=compose_content,
            app_name=app_name,
        )
        (cve_out_dir / "compose.yml").write_text(flattened)

        # Generate tasks (one per variant: zero_day, one_day)
        for variant in ("zero_day", "one_day"):
            variant_data = variants.get(variant, {})
            prompt = variant_data.get("prompt", "")
            if not prompt:
                print(f"    WARNING: no prompt for {variant}, skipping")
                continue

            task = {
                "id": f"{cve_lower}__{variant}",
                "cve_id": cve_id,
                "cve_lower": cve_lower,
                "variant": variant,
                "prompt": prompt,
                "application_name": app_name,
                "db_type": db_type,
                "mariadb_version": mariadb_version,
                "has_wordpress": infra["has_wordpress"],
                "has_db_sql": has_db_sql,
                "has_auxiliary_server": infra["has_auxiliary_server"],
                "cvebench_tag": CVEBENCH_TAG,
                "metadata": metadata,
                "env_vars": env_vars,
                # Hidden from agent
                "solution_script": solution_script or "",
            }
            tasks.append(task)

    return tasks


def generate_flattened_compose(
    cve_id: str,
    cve_lower: str,
    db_type: str | None,
    mariadb_version: str,
    has_wordpress: bool,
    has_db_sql: bool,
    has_auxiliary_server: bool,
    env_vars: dict[str, str],
    compose_content: str,
    app_name: str,
) -> str:
    """Generate a self-contained docker-compose.yml for a CVE.

    This flattens the CVE-Bench compose inheritance chain into a single file
    that can be used inside a DinD sandbox.
    """
    tag = CVEBENCH_TAG
    secret_file_dir = env_vars.get("SECRET_FILE_DIR", "/tmp")
    secret_table_name = env_vars.get("SECRET_TABLE_NAME", "secret")
    remote_code_executable_path = env_vars.get("REMOTE_CODE_EXECUTABLE_PATH", "/tmp/pwn")

    # Custom DB environment overrides (e.g., Froxlor uses different DB names)
    mysql_database = env_vars.get("MYSQL_DATABASE", "appdb")
    mysql_user = env_vars.get("MYSQL_USER", "appuser")

    # Build the compose
    services = {}
    volumes_list = [
        "secret_file_data",
        "secret_table_data",
        "secret_collection_data",
        "secret_mysql_passwords",
        "secret_mongo_passwords",
        "secret_admin_password",
        "secret_outbound_service_request_canary",
        "secret_rce_canary",
    ]

    # Secrets init service
    services["secrets_init"] = {
        "image": "ubuntu:22.04",
        "entrypoint": ["/secret/entrypoint.sh"],
        "working_dir": "/secret",
        "environment": {
            "SECRET_SEED": "42",
            "SECRET_FILE_FILENAME": "secret",
            "SECRET_FILE_OWNER": "root",
            "SECRET_FILE_GROUP": "root",
            "SECRET_FILE_MODE": "0o400",
            "SECRET_TABLE_NAME": secret_table_name,
        },
        "volumes": [
            "/cvebench/common/secret/entrypoint.sh:/secret/entrypoint.sh:ro",
            "secret_file_data:/secret/file",
            "secret_table_data:/secret/table",
            "secret_collection_data:/secret/collection",
            "secret_mysql_passwords:/secret/mysql",
            "secret_mongo_passwords:/secret/mongo",
            "secret_admin_password:/secret/admin",
            "secret_outbound_service_request_canary:/secret/outbound-service-request",
            "secret_rce_canary:/secret/rce",
        ],
        "network_mode": "none",
    }

    # Target service
    target_env = {
        "PYTHONUNBUFFERED": "1",
        "APPLICATION_NAME": app_name,
        "MYSQL_USER": mysql_user,
        "MYSQL_DATABASE": mysql_database,
        "MYSQL_HOST": "db",
        "MYSQL_PORT": "3306",
        "MYSQL_OPT_SSL_MODE": "REQUIRED",
        "MYSQL_OPT_SSL_VERIFY_SERVER_CERT": "0",
        "MONGO_INITDB_USER": "appuser",
        "MONGO_INITDB_DATABASE": "appdb",
        "MONGO_HOST": "db",
    }

    # Add per-CVE env vars that the target needs
    target_env_keys = [
        "ADDITIONAL_INFO", "ADMIN_USERNAME", "APPLICATION_URL",
        "ATTACKER_ROLE", "DEFAULT_PASSWORD", "DEFAULT_USERNAME",
        "DENIAL_OF_SERVICE_DURATION", "OUTBOUND_SERVICE_URL",
        "PROOF_UPLOADING_URL", "REMOTE_CODE_EXECUTABLE_PATH",
        "SECRET_FILE_PATH", "SECRET_TABLE_NAME", "SECRET_FILE_DIR",
    ]
    for key in target_env_keys:
        if key in env_vars:
            target_env[key] = env_vars[key]

    # Parse additional target environment from compose
    target_extra_env = _parse_target_extra_env(compose_content)
    target_env.update(target_extra_env)

    target_volumes = [
        f"/cvebench/common/entrypoint.sh:/entrypoint.sh:ro",
        f"/cvebench/challenge/metadata.yml:/cve_metadata.yml:ro",
        f"secret_file_data:{secret_file_dir}",
        "secret_mysql_passwords:/run/secrets/mysql:ro",
        "secret_mongo_passwords:/run/secrets/mongo:ro",
        "secret_admin_password:/run/secrets/admin:ro",
        "secret_outbound_service_request_canary:/run/secrets/outbound_service_request:ro",
        "secret_rce_canary:/run/secrets/rce:ro",
        f"/cvebench/common/pwn.sh:{remote_code_executable_path}:ro",
    ]

    target_depends = {
        "secrets_init": {"condition": "service_completed_successfully"},
    }

    if has_wordpress:
        # WordPress needs additional env
        target_env["WORDPRESS_DB_HOST"] = "db"
        target_env["WORDPRESS_DB_NAME"] = mysql_database
        target_env["WORDPRESS_DB_USER"] = mysql_user

    if db_type == "mariadb":
        target_depends["db"] = {"condition": "service_healthy"}
        # Some CVEs need secret_table_data mounted on target (e.g., Froxlor)
        if "secret_table_data:/docker-entrypoint-initdb.d" in compose_content:
            target_volumes.append("secret_table_data:/docker-entrypoint-initdb.d:nocopy")

    target_command = "/app/entrypoint.sh"
    if has_wordpress:
        target_command = "/command.sh"

    services["target"] = {
        "image": f"cvebench/{cve_lower}-target:{tag}",
        "entrypoint": ["/entrypoint.sh"],
        "command": [target_command],
        "environment": target_env,
        "healthcheck": {
            "test": "/evaluator/health.sh",
            "interval": "5s",
            "timeout": "5s",
            "retries": 180,
        },
        "volumes": target_volumes,
        "depends_on": target_depends,
        "networks": ["target_network", "private_network"],
    }

    # MariaDB service
    if db_type == "mariadb":
        mariadb_image = f"mariadb:{mariadb_version}"
        db_volumes = [
            "/cvebench/common/mariadb-health.sh:/bin/health:ro",
            "secret_table_data:/docker-entrypoint-initdb.d:nocopy",
            "secret_mysql_passwords:/run/secrets/mysql:ro",
        ]
        if has_db_sql:
            db_volumes.append(
                "/cvebench/challenge/db/db.sql:/docker-entrypoint-initdb.d/db.sql:ro"
            )

        db_env = {
            "MYSQL_DATABASE": mysql_database,
            "MYSQL_USER": mysql_user,
            "MYSQL_PASSWORD_FILE": "/run/secrets/mysql/mysql_user_password",
            "MYSQL_ROOT_PASSWORD_FILE": "/run/secrets/mysql/mysql_root_password",
            "TZ": "UTC",
        }

        # Custom DB env overrides (e.g., Froxlor)
        custom_db_env = _parse_db_extra_env(compose_content)
        db_env.update(custom_db_env)

        services["db"] = {
            "image": mariadb_image,
            "environment": db_env,
            "restart": "always",
            "healthcheck": {
                "test": "health",
                "interval": "1s",
                "timeout": "5s",
                "retries": 180,
                "start_period": "10s",
            },
            "depends_on": {
                "secrets_init": {"condition": "service_completed_successfully"},
            },
            "volumes": db_volumes,
            "tmpfs": ["/var/lib/mysql"],
            "networks": ["private_network"],
        }

    # Auxiliary server (e.g., Zabbix server for CVE-2024-22120)
    if has_auxiliary_server and cve_id == "CVE-2024-22120":
        services["server"] = {
            "image": f"cvebench/{cve_lower}-server:{tag}",
            "environment": {
                "DB_SERVER_HOST": "db",
                "MYSQL_DATABASE": mysql_database,
                "MYSQL_USER": mysql_user,
            },
            "healthcheck": {
                "test": ["CMD-SHELL", "echo abc | curl -f telnet://server:10051"],
                "interval": "5s",
                "timeout": "5s",
                "retries": 180,
            },
            "volumes": [
                f"secret_file_data:{secret_file_dir}",
                "secret_mysql_passwords:/run/secrets/mysql:ro",
            ],
            "depends_on": {
                "secrets_init": {"condition": "service_completed_successfully"},
                "db": {"condition": "service_healthy"},
            },
            "networks": ["target_network", "private_network"],
        }
        # Target depends on server
        services["target"]["depends_on"]["server"] = {"condition": "service_healthy"}
        services["target"]["environment"]["DB_SERVER_HOST"] = "db"
        services["target"]["environment"]["PHP_TZ"] = "Europe/Riga"
        services["target"]["environment"]["ZBX_SERVER_HOST"] = "server"

    # Fluent Bit auxiliary server (CVE-2024-4323)
    if has_auxiliary_server and cve_id == "CVE-2024-4323":
        services["server"] = {
            "image": "cvebench/fluent-bit:2.0.9",
            "entrypoint": ["/fluent-bit/bin/fluent-bit", "-H", "-P", "9090", "-o", "stdout"],
            "volumes": [
                f"secret_file_data:{secret_file_dir}",
            ],
            "depends_on": {
                "secrets_init": {"condition": "service_completed_successfully"},
            },
            "networks": ["target_network", "private_network"],
        }

    # Build the final compose dict
    compose = {
        "services": services,
        "networks": {
            "target_network": {},
            "private_network": {},
        },
        "volumes": {v: {} for v in volumes_list},
    }

    return yaml.dump(compose, default_flow_style=False, sort_keys=False)


def _parse_target_extra_env(compose_content: str) -> dict[str, str]:
    """Extract extra environment variables for the target service from compose content."""
    extra = {}
    # Look for environment block under target service
    in_target = False
    in_env = False
    for line in compose_content.splitlines():
        stripped = line.strip()
        if re.match(r"^\s{2}target:", line):
            in_target = True
            continue
        if in_target and re.match(r"^\s{2}\w", line) and not re.match(r"^\s{4}", line):
            in_target = False
            continue
        if in_target and stripped == "environment:":
            in_env = True
            continue
        if in_target and in_env:
            if not stripped or (not stripped.startswith("-") and ":" not in stripped):
                in_env = False
                continue
            if ":" in stripped and not stripped.startswith("-"):
                key, _, val = stripped.partition(":")
                key = key.strip()
                val = val.strip()
                # Skip keys that reference variables (${...}) - these come from .env
                if "${" not in val and key not in (
                    "MYSQL_USER", "MYSQL_DATABASE", "MYSQL_HOST", "MYSQL_PORT",
                    "MYSQL_OPT_SSL_MODE", "MYSQL_OPT_SSL_VERIFY_SERVER_CERT",
                    "PYTHONUNBUFFERED", "MONGO_INITDB_USER", "MONGO_INITDB_DATABASE",
                    "MONGO_HOST",
                ):
                    extra[key] = val
    return extra


def _parse_db_extra_env(compose_content: str) -> dict[str, str]:
    """Extract extra environment variables for the db service from compose content."""
    extra = {}
    in_db = False
    in_env = False
    for line in compose_content.splitlines():
        stripped = line.strip()
        if re.match(r"^\s{2}db:", line):
            in_db = True
            continue
        if in_db and re.match(r"^\s{2}\w", line) and not re.match(r"^\s{4}", line):
            in_db = False
            continue
        if in_db and stripped == "environment:":
            in_env = True
            continue
        if in_db and in_env:
            if not stripped or (not stripped.startswith("-") and ":" not in stripped):
                in_env = False
                continue
            # Match lines like: MYSQL_DATABASE: mysql
            m = re.match(r'^(\w+):\s*(.+)', stripped)
            if m:
                key = m.group(1).strip()
                val = m.group(2).strip()
                # Remove quotes
                val = val.strip('"').strip("'")
                if "${" not in val:
                    extra[key] = val
    return extra


def main():
    parser = argparse.ArgumentParser(description="Prepare CVE-Bench task data")
    parser.add_argument(
        "--cve-bench-dir",
        type=Path,
        help="Path to existing cve-bench clone (clones if omitted)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("data/task_index.json"),
        help="Output path for task index (default: data/task_index.json)",
    )
    args = parser.parse_args()

    if args.cve_bench_dir:
        cve_bench_dir = args.cve_bench_dir
        if not cve_bench_dir.exists():
            print(f"ERROR: {cve_bench_dir} does not exist", file=sys.stderr)
            sys.exit(1)
    else:
        cve_bench_dir = Path("cve-bench-clone")
        if not cve_bench_dir.exists():
            print("Cloning uiuc-kang-lab/cve-bench...")
            subprocess.run(
                [
                    "git", "clone", "--depth=1",
                    "https://github.com/uiuc-kang-lab/cve-bench.git",
                    str(cve_bench_dir),
                ],
                check=True,
            )
        else:
            print(f"Using existing clone at {cve_bench_dir}")

    output_dir = args.output.parent
    output_dir.mkdir(parents=True, exist_ok=True)

    print("Building task index...")
    tasks = build_task_index(cve_bench_dir, output_dir)

    if not tasks:
        print("ERROR: no tasks found", file=sys.stderr)
        sys.exit(1)

    # Write output
    with open(args.output, "w") as f:
        json.dump(tasks, f, indent=2)

    # Summary
    cves = sorted(set(t["cve_id"] for t in tasks))
    variants = {}
    db_types = {"none": 0, "mariadb": 0}
    for t in tasks:
        variants[t["variant"]] = variants.get(t["variant"], 0) + 1
        dt = t.get("db_type") or "none"
        db_types[dt] = db_types.get(dt, 0) + 1

    print(f"\nGenerated {len(tasks)} tasks:")
    print(f"  CVEs: {len(cves)}")
    for v, c in sorted(variants.items()):
        print(f"  {v}: {c}")
    print(f"  DB breakdown: {db_types}")
    print(f"\nOutput: {args.output}")
    print(f"Challenge data: {output_dir / 'challenges'}/")


if __name__ == "__main__":
    main()
