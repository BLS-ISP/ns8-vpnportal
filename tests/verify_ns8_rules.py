#!/usr/bin/env python3
"""Automated NethServer 8 (NS8) architectural & security rule audit for ns8-vpn."""

from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_NS8_I18N_KEYS = {
    "action.list-installed-modules",
    "task.cannot_create_task",
    "error.cannot_retrieve_installed_modules",
    "error.cannot_retrieve_module_info",
}

BINARY_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".db",
    ".sqlite",
}


def flatten_json_keys(obj: Any, prefix: str = "") -> set[str]:
    """Flatten nested JSON dictionary keys into dot-separated leaf paths."""
    keys: set[str] = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            full_key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and v:
                keys.update(flatten_json_keys(v, full_key))
            else:
                keys.add(full_key)
    return keys


def iter_clean_files(base: Path) -> list[Path]:
    """Yield non-bytecode, non-cache files under `base`."""
    if not base.exists():
        return []
    files: list[Path] = []
    for p in sorted(base.rglob("*")):
        if not p.is_file():
            continue
        if (
            ".venv" in p.parts
            or ".git" in p.parts
            or "__pycache__" in p.parts
            or ".pytest_cache" in p.parts
            or "node_modules" in p.parts
            or "dist" in p.parts
        ):
            continue
        if p.suffix.lower() in BINARY_SUFFIXES:
            continue
        files.append(p)
    return files


def check_no_custom_get_status(errors: list[str]) -> None:
    get_status_path = REPO_ROOT / "imageroot" / "actions" / "get-status"
    if get_status_path.exists():
        errors.append(
            f"[NS8-RULE-1] Forbidden custom action exists: {get_status_path.relative_to(REPO_ROOT)} "
            "(NS8 core provides /usr/local/agent/actions/get-status/20read)."
        )


def check_dump_env_after_set_env(errors: list[str]) -> None:
    imageroot = REPO_ROOT / "imageroot"
    checked = 0
    for file_path in iter_clean_files(imageroot):
        text = file_path.read_text(encoding="utf-8", errors="replace")
        if "set_env" not in text:
            continue
        checked += 1
        rel = file_path.relative_to(REPO_ROOT)
        try:
            tree = ast.parse(text, filename=str(rel))
        except SyntaxError as exc:
            errors.append(f"[NS8-RULE-2] Python syntax error in {rel}: {exc}")
            continue

        set_env_lines: list[int] = []
        dump_env_lines: list[int] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "set_env":
                    set_env_lines.append(node.lineno)
                elif node.func.attr == "dump_env":
                    dump_env_lines.append(node.lineno)

        if set_env_lines:
            if not dump_env_lines:
                errors.append(f"[NS8-RULE-2] {rel} calls agent.set_env() without calling agent.dump_env()!")
            elif max(dump_env_lines) < max(set_env_lines):
                errors.append(
                    f"[NS8-RULE-2] {rel} has agent.set_env() at line {max(set_env_lines)} "
                    f"after last agent.dump_env() at line {max(dump_env_lines)}!"
                )
    if checked == 0:
        errors.append("[NS8-RULE-2] Expected at least one imageroot action calling agent.set_env() + agent.dump_env().")


def check_systemd_units(errors: list[str]) -> None:
    imageroot = REPO_ROOT / "imageroot"
    service_files = [p for p in iter_clean_files(imageroot) if p.suffix == ".service"]
    if not service_files:
        errors.append("[NS8-RULE-3] Missing systemd unit file in imageroot/ (expected imageroot/vpn-controller.service).")
        return

    for svc in service_files:
        rel = svc.relative_to(REPO_ROOT)
        content = svc.read_text(encoding="utf-8", errors="replace")
        if "--pull=always" in content:
            errors.append(f"[NS8-RULE-3] Forbidden '--pull=always' found in {rel} (must use '--pull=missing').")
        if "--pull=missing" not in content:
            errors.append(f"[NS8-RULE-3] Missing '--pull=missing' in {rel}.")
        if "EnvironmentFile=/var/lib/nethserver/%N/state/environment" not in content:
            errors.append(f"[NS8-RULE-3] Missing rootful EnvironmentFile=/var/lib/nethserver/%N/state/environment in {rel}.")


def check_containerfile_and_lifecycle(errors: list[str]) -> None:
    cfile = REPO_ROOT / "Containerfile"
    if not cfile.is_file():
        errors.append("[NS8-RULE-4] Missing root Containerfile.")
    else:
        content = cfile.read_text(encoding="utf-8", errors="replace")
        required_tokens = [
            "org.nethserver.rootfull=1",
            "org.nethserver.max-per-node=1",
            "org.nethserver.tcp-ports-demand=1",
            "traefik@node:routeadm",
            "ldapproxy@node:accountconsumer",
            "node:fwadm",
            "org.nethserver.min-core",
            "/imageroot/actions/*/[0-9]*",
        ]
        for token in required_tokens:
            if token not in content:
                errors.append(f"[NS8-RULE-4] Root Containerfile missing required label/token: {token}")
        _, _, scratch_stage = content.rpartition("FROM scratch")
        if "ENTRYPOINT" not in scratch_stage:
            errors.append(
                "[NS8-RULE-4] Root Containerfile final 'FROM scratch' stage missing ENTRYPOINT "
                "(required by NS8 'podman create' during extract-image)."
            )

    required_paths = [
        "imageroot/vpn-controller.service",
        "imageroot/update-module.d/10setup",
        "imageroot/etc/state-include.conf",
        "imageroot/bin/module-dump-state",
        "imageroot/bin/module-cleanup-state",
        "imageroot/actions/create-module/10setup",
        "imageroot/actions/create-module/20initialize",
        "imageroot/actions/configure-module/01hostname-validation",
        "imageroot/actions/configure-module/10validate",
        "imageroot/actions/configure-module/20configure",
        "imageroot/actions/configure-module/80start_services",
        "imageroot/actions/get-configuration/10get",
        "imageroot/actions/list-user-domains/10list",
        "imageroot/actions/list-domain-groups/10list",
        "imageroot/actions/list-peers/10list",
        "imageroot/actions/create-peer/20create",
        "imageroot/actions/get-peer-config/10get",
        "imageroot/actions/toggle-peer/20toggle",
        "imageroot/actions/revoke-peer/20revoke",
        "imageroot/actions/sync-users/20sync",
        "imageroot/actions/reset-user-totp/20reset",
        "imageroot/actions/get-user-ovpn/10get",
        "imageroot/actions/list-s2s-tunnels/10list",
        "imageroot/actions/create-s2s-tunnel/20create",
        "imageroot/actions/get-s2s-config/10get",
        "imageroot/actions/toggle-s2s-tunnel/20toggle",
        "imageroot/actions/delete-s2s-tunnel/20delete",
        "imageroot/actions/list-audit-logs/10list",
        "imageroot/actions/list-audit-logs/validate-input.json",
        "imageroot/actions/list-audit-logs/validate-output.json",
        "tests/ns8_smoke_test.sh",
        "imageroot/actions/restore-module/06copyenv",
        "imageroot/actions/restore-module/10setup",
        "imageroot/actions/restore-module/50configure",
        "imageroot/actions/clone-module/50configure",
        "imageroot/actions/destroy-module/20destroy",
        "imageroot/actions/destroy-module/90systemd",
        "imageroot/events/service-ldap-changed/10reload",
        "imageroot/events/user-domain-changed/10reload",
    ]
    for rel_str in required_paths:
        if not (REPO_ROOT / rel_str).is_file():
            errors.append(f"[NS8-RULE-4] Missing required NS8 module file: {rel_str}")

    for file_path in iter_clean_files(REPO_ROOT / "imageroot"):
        rel = file_path.relative_to(REPO_ROOT)
        text = file_path.read_text(encoding="utf-8", errors="replace")
        if "LdapProxy" in text:
            errors.append(f"[NS8-RULE-4] Invalid casing 'LdapProxy' in {rel} (must be 'Ldapproxy' with lowercase p).")
        if re.search(r"--zone=trusted[^\n]*--add-interface|--add-interface[^\n]*--zone=trusted", text):
            errors.append(f"[NS8-RULE-4] Forbidden addition of VPN interface to NS8 'trusted' zone in {rel}.")
        if file_path.suffix == ".json":
            try:
                json.loads(text)
            except ValueError as exc:
                errors.append(f"[NS8-RULE-4] Invalid JSON in {rel}: {exc}")


def check_lf_line_endings(errors: list[str]) -> None:
    gitattributes = REPO_ROOT / ".gitattributes"
    if not gitattributes.is_file():
        errors.append("[NS8-RULE-5] Missing .gitattributes.")
    else:
        ga_text = gitattributes.read_text(encoding="utf-8", errors="replace")
        for pattern in ("imageroot/**", "container/**", "*.sh", "Containerfile"):
            if pattern not in ga_text or "eol=lf" not in ga_text:
                errors.append(f"[NS8-RULE-5] .gitattributes must enforce eol=lf for '{pattern}'.")

    targets: list[Path] = []
    targets.extend(iter_clean_files(REPO_ROOT / "imageroot"))
    if (REPO_ROOT / "container").exists():
        targets.extend(iter_clean_files(REPO_ROOT / "container"))
    if (REPO_ROOT / "tests").exists():
        targets.extend(iter_clean_files(REPO_ROOT / "tests"))
    if (REPO_ROOT / "ui").exists():
        targets.extend(iter_clean_files(REPO_ROOT / "ui"))
    if (REPO_ROOT / ".github").exists():
        targets.extend(iter_clean_files(REPO_ROOT / ".github"))
    smoke_script = REPO_ROOT / "tests" / "ns8_smoke_test.sh"
    if smoke_script.is_file():
        targets.append(smoke_script)
        smoke_head = smoke_script.read_bytes()[:64]
        if not smoke_head.startswith(b"#!/usr/bin/env bash\n"):
            errors.append(
                "[NS8-RULE-5] tests/ns8_smoke_test.sh must start with LF shebang '#!/usr/bin/env bash\\n'."
            )
    for root_file in REPO_ROOT.glob("*.sh"):
        if root_file.is_file():
            targets.append(root_file)
    for extra in (
        REPO_ROOT / "Containerfile",
        REPO_ROOT / ".gitattributes",
        REPO_ROOT / ".gitignore",
        REPO_ROOT / "README.md",
    ):
        if extra.is_file():
            targets.append(extra)

    seen: set[Path] = set()
    for path in targets:
        if path in seen:
            continue
        seen.add(path)
        raw = path.read_bytes()
        if b"\r" in raw:
            errors.append(f"[NS8-RULE-5] CRLF / CR byte detected in {path.relative_to(REPO_ROOT)} (must be strict LF).")


def check_ui_rules(errors: list[str], notices: list[str]) -> None:
    ui_dir = REPO_ROOT / "ui"
    if not ui_dir.exists():
        notices.append("[SKIP] ui/ directory not created yet; skipping UI i18n and TaskService checks.")
        return

    ui_src = ui_dir / "src"
    if ui_src.exists():
        for src_file in iter_clean_files(ui_src):
            if src_file.suffix.lower() in {".vue", ".js", ".ts"}:
                text = src_file.read_text(encoding="utf-8", errors="replace")
                if "createSuccessNotificationForApp" in text:
                    errors.append(
                        f"[NS8-UI-RULE-1] Forbidden non-existent API 'createSuccessNotificationForApp' "
                        f"used in {src_file.relative_to(REPO_ROOT)}."
                    )

    de_path = ui_dir / "public" / "i18n" / "de" / "translation.json"
    en_path = ui_dir / "public" / "i18n" / "en" / "translation.json"

    if not de_path.is_file() or not en_path.is_file():
        notices.append("[SKIP] ui/public/i18n/{de,en}/translation.json not both present yet; skipping i18n parity check.")
        return

    try:
        de_data = json.loads(de_path.read_text(encoding="utf-8"))
        en_data = json.loads(en_path.read_text(encoding="utf-8"))
    except ValueError as exc:
        errors.append(f"[NS8-UI-RULE-3] Invalid JSON in translation files: {exc}")
        return

    de_keys = flatten_json_keys(de_data)
    en_keys = flatten_json_keys(en_data)

    only_de = sorted(de_keys - en_keys)
    only_en = sorted(en_keys - de_keys)
    if only_de:
        errors.append(f"[NS8-UI-RULE-3] Keys in de/translation.json missing from en/translation.json: {only_de[:10]}")
    if only_en:
        errors.append(f"[NS8-UI-RULE-3] Keys in en/translation.json missing from de/translation.json: {only_en[:10]}")

    for req_key in sorted(REQUIRED_NS8_I18N_KEYS):
        if req_key not in en_keys:
            errors.append(f"[NS8-UI-RULE-3] Mandatory NS8 i18n key '{req_key}' missing from en/translation.json.")
        if req_key not in de_keys:
            errors.append(f"[NS8-UI-RULE-3] Mandatory NS8 i18n key '{req_key}' missing from de/translation.json.")

    notices.append(f"[OK] Verified {len(en_keys)} matching i18n keys across de & en translations.")


def check_no_reserved_vpn_image_id(errors: list[str]) -> None:
    """Forbid bare `/vpn` module image basename.

    In ns8-core, `add-module` sets Redis STRING `node/<id>/default_instance/<image_id>`.
    Meanwhile, `get-cluster-status/50read` runs `rdb.scan_iter('node/*/vpn')` and calls
    `rdb.hgetall(...)`, which crashes with `WRONGTYPE` if `<image_id>` is `vpn`!
    """
    meta_path = REPO_ROOT / "ui" / "public" / "metadata.json"
    if meta_path.is_file():
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        source = str(meta.get("source") or "").strip().rstrip("/")
        if source.endswith("/vpn") or source == "vpn":
            errors.append(
                f"[NS8-RULE-6] metadata.json 'source' ({source}) must NOT use reserved basename 'vpn' "
                "(collides with ns8-core rdb.scan_iter('node/*/vpn') -> Redis WRONGTYPE)."
            )

    build_sh = REPO_ROOT / "build-images.sh"
    if build_sh.is_file():
        btext = build_sh.read_text(encoding="utf-8", errors="replace")
        if re.search(r'module_image="\$\{repobase\}/vpn"', btext):
            errors.append(
                "[NS8-RULE-6] build-images.sh module_image must NOT be '${repobase}/vpn' "
                "(collides with ns8-core rdb.scan_iter('node/*/vpn') -> Redis WRONGTYPE)."
            )


def main() -> int:
    errors: list[str] = []
    notices: list[str] = []

    check_no_custom_get_status(errors)
    check_dump_env_after_set_env(errors)
    check_systemd_units(errors)
    check_containerfile_and_lifecycle(errors)
    check_lf_line_endings(errors)
    check_ui_rules(errors, notices)
    check_no_reserved_vpn_image_id(errors)

    for note in notices:
        print(note)

    if errors:
        print("\nNS8 Rule Audit FAILED with the following issues:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("NS8 Rule Audit PASSED: all rootful module, systemd, env, LF, and UI rules verified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
