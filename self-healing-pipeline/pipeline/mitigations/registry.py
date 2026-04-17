"""
Mitigation registry.

Loads mitigations.json and exposes lookup(vuln_type) → mitigation dict.
Also provides apply(mitigation, config) which dispatches to the right handler.
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

_MITIGATIONS_FILE = Path(__file__).parent.parent.parent / "mitigations.json"
_SNIPPETS_DIR     = Path(__file__).parent.parent / "snippets"

_registry: dict = {}


def load():
    global _registry
    with open(_MITIGATIONS_FILE) as f:
        _registry = json.load(f)
    log.info("Loaded %d mitigations from %s", len(_registry), _MITIGATIONS_FILE)


def lookup(vuln_type: str) -> Optional[dict]:
    """Return the mitigation dict for a vuln_type, or None if unmapped."""
    if not _registry:
        load()
    return _registry.get(vuln_type)


def apply(mitigation: dict, config: dict) -> bool:
    """
    Dispatch to the appropriate mitigation handler based on mitigation["type"].
    Returns True if the mitigation was applied successfully.
    """
    mit_type = mitigation.get("type")
    mid      = mitigation.get("id", "?")

    log.info("Applying mitigation %s (%s) via %s", mid, mitigation.get("description",""), mit_type)

    try:
        if mit_type == "nginx_rule":
            return _apply_nginx_rule(mitigation, config)
        elif mit_type == "env_var":
            return _apply_env_var(mitigation, config)
        elif mit_type == "docker_restart":
            return _apply_docker_restart(mitigation, config)
        else:
            log.warning("Unknown mitigation type: %s", mit_type)
            return False
    except Exception as e:
        log.error("Error applying mitigation %s: %s", mid, e)
        return False


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------

def _apply_nginx_rule(mitigation: dict, config: dict) -> bool:
    """
    Append a nginx snippet to the active nginx config dir and reload nginx.

    Expects mitigation["action"] = filename relative to pipeline/snippets/
    Nginx conf.d dir is taken from config["nginx_conf_d"] or detected.
    """
    snippet_name = mitigation.get("action", "")
    snippet_path = _SNIPPETS_DIR / snippet_name

    if not snippet_path.exists():
        log.error("Nginx snippet not found: %s", snippet_path)
        return False

    conf_d = Path(config.get("nginx_conf_d", "/etc/nginx/conf.d"))

    if not conf_d.exists():
        # Try docker exec approach
        return _apply_nginx_via_docker(snippet_path, snippet_name, config)

    dest = conf_d / f"selfheal_{snippet_name}"
    shutil.copy(snippet_path, dest)
    log.info("Copied %s → %s", snippet_name, dest)

    # Reload nginx
    result = subprocess.run(["nginx", "-s", "reload"], capture_output=True, text=True)
    if result.returncode != 0:
        log.error("nginx reload failed: %s", result.stderr)
        return False

    log.info("nginx reloaded successfully")
    return True


def _apply_nginx_via_docker(snippet_path: Path, snippet_name: str, config: dict) -> bool:
    """Apply nginx rule to a Docker-managed nginx container."""
    container = config.get("nginx_container", "crapi-web")

    # Copy snippet into container
    cp_result = subprocess.run(
        ["docker", "cp", str(snippet_path), f"{container}:/etc/nginx/conf.d/selfheal_{snippet_name}"],
        capture_output=True, text=True
    )
    if cp_result.returncode != 0:
        log.error("docker cp failed: %s", cp_result.stderr)
        return False

    # Test and reload
    test = subprocess.run(
        ["docker", "exec", container, "nginx", "-t"],
        capture_output=True, text=True
    )
    if test.returncode != 0:
        log.error("nginx -t failed: %s", test.stderr)
        return False

    reload = subprocess.run(
        ["docker", "exec", container, "nginx", "-s", "reload"],
        capture_output=True, text=True
    )
    if reload.returncode != 0:
        log.error("nginx reload failed: %s", reload.stderr)
        return False

    log.info("nginx reloaded in container %s", container)
    return True


def _apply_env_var(mitigation: dict, config: dict) -> bool:
    """
    Write environment variables to a .env file and restart the affected
    Docker service.

    mitigation["action"] = { "VAR_NAME": "value", ... }
    mitigation["applies_to"] = docker service name
    """
    env_vars   = mitigation.get("action", {})
    service    = mitigation.get("applies_to", "")
    env_file   = Path(config.get("env_file", ".env"))

    # Read existing .env
    existing = {}
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                existing[k.strip()] = v.strip()

    # Merge new vars
    existing.update(env_vars)

    # Write back
    lines = [f"{k}={v}" for k, v in existing.items()]
    env_file.write_text("\n".join(lines) + "\n")
    log.info("Updated %s with %s", env_file, env_vars)

    # Restart the affected service
    if service and shutil.which("docker"):
        result = subprocess.run(
            ["docker", "compose", "restart", service],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            log.warning("docker compose restart %s failed: %s", service, result.stderr)
            return False
        log.info("Restarted service: %s", service)

    return True


def _apply_docker_restart(mitigation: dict, config: dict) -> bool:
    """Simply restart a Docker service (e.g. after a config file change)."""
    service = mitigation.get("applies_to", "")
    if not service:
        log.error("docker_restart mitigation missing 'applies_to'")
        return False

    result = subprocess.run(
        ["docker", "compose", "restart", service],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        log.error("docker compose restart %s: %s", service, result.stderr)
        return False

    log.info("Restarted %s", service)
    return True
