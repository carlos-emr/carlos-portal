import os
import subprocess
from hashlib import sha256
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).parents[1]
DEPLOY_SCRIPT = REPOSITORY_ROOT / "scripts" / "production-deploy"


def rollback_environment(tmp_path: Path, fake_docker: Path) -> dict[str, str]:
    environment_files = []
    for name in (
        "production.env",
        "outbox.env",
        "migration.env",
        "database-admin.env",
        "maintenance.env",
    ):
        path = tmp_path / name
        path.write_text("TEST_ONLY=true\n")
        path.chmod(0o600)
        environment_files.append(path)
    ca_file = tmp_path / "postgresql-ca.pem"
    ca_file.write_text("test CA\n")
    return {
        **os.environ,
        "PATH": f"{fake_docker.parent}:{os.environ['PATH']}",
        "PORTAL_IMAGE": f"registry.example/current@sha256:{'a' * 64}",
        "PORTAL_ROLLBACK_IMAGE": f"registry.example/previous@sha256:{'b' * 64}",
        "PORTAL_ENV_FILE": str(environment_files[0]),
        "PORTAL_OUTBOX_ENV_FILE": str(environment_files[1]),
        "PORTAL_MIGRATION_ENV_FILE": str(environment_files[2]),
        "PORTAL_DATABASE_ADMIN_ENV_FILE": str(environment_files[3]),
        "PORTAL_MAINTENANCE_ENV_FILE": str(environment_files[4]),
        "PORTAL_DB_CA_FILE": str(ca_file),
        "PORTAL_DEPLOY_LOCK_FILE": str(tmp_path / "deploy.lock"),
        "FAKE_DOCKER_LOG": str(tmp_path / "docker.log"),
        "FAKE_WEB_OUTBOX_DIGEST": "c" * 64,
        "FAKE_WORKER_OUTBOX_DIGEST": "c" * 64,
        "FAKE_WEB_DATABASE_PROBE": "31|32|33|" + "d" * 64 + "|tls|safe",
        "FAKE_WORKER_DATABASE_PROBE": "31|32|33|" + "d" * 64 + "|tls|safe",
    }


def install_fake_docker(tmp_path: Path, *, fail_preflight: bool) -> Path:
    executable = tmp_path / "docker"
    failure = "exit 23" if fail_preflight else "exit 0"
    executable.write_text(
        "#!/bin/sh\n"
        "printf '%s|%s\\n' \"$PORTAL_IMAGE\" \"$*\" >> \"$FAKE_DOCKER_LOG\"\n"
        "case \"$*\" in\n"
        "  *'outbox-configuration-sha256'*) "
        "case \"$*\" in *' outbox outbox-configuration-sha256'*) "
        "printf '%s\\n' \"$FAKE_WORKER_OUTBOX_DIGEST\" ;; "
        "*) printf '%s\\n' \"$FAKE_WEB_OUTBOX_DIGEST\" ;; esac; exit 0 ;;\n"
        "  *'deployment-probe database-artifacts-sha256'*) "
        "printf '%s\\n' \"${FAKE_ARTIFACT_OUTPUT:-}\"; exit 0 ;;\n"
        "  *'/policy/postgresql-database-identity.sql'*) "
        "printf '%s\\n' \"${FAKE_ADMIN_DATABASE_PROBE:-}\"; exit 0 ;;\n"
        "  *'deployment-probe migration'*) "
        "printf '%s\\n' \"${FAKE_MIGRATION_DATABASE_PROBE:-}\"; exit 0 ;;\n"
        "  *'deployment-probe runtime'*) "
        "if [ \"${FAKE_REQUIRE_POLICY_FIRST:-false}\" = true ] "
        "&& [ ! -f \"$FAKE_POLICY_STATE\" ]; then exit 29; fi; "
        "printf '%s\\n' \"$FAKE_WEB_DATABASE_PROBE\"; exit 0 ;;\n"
        "  *'outbox outbox'*) "
        "if [ \"${FAKE_REQUIRE_POLICY_FIRST:-false}\" = true ] "
        "&& [ ! -f \"$FAKE_POLICY_STATE\" ]; then exit 29; fi; "
        "printf '%s\\n' \"$FAKE_WORKER_DATABASE_PROBE\"; exit 0 ;;\n"
        "  *'audit-maintenance maintenance'*) "
        "if [ \"${FAKE_REQUIRE_POLICY_FIRST:-false}\" = true ] "
        "&& [ ! -f \"$FAKE_POLICY_STATE\" ]; then exit 29; fi; "
        "printf '%s\\n' \"${FAKE_MAINTENANCE_DATABASE_PROBE:-}\"; exit 0 ;;\n"
        "  *'hasattr(c, \"get_outbox_settings\") else 42'*) "
        "if [ \"${FAKE_OUTBOX_PROBE_FAILURE:-false}\" = true ]; then exit 23; fi; "
        "if [ \"${FAKE_LEGACY_OUTBOX_IMAGE:-false}\" = true ]; then exit 42; fi ;;\n"
        "  *'up --detach'*) "
        "if [ -n \"${FAKE_OUTBOX_ENV_LOG:-}\" ]; then "
        "printf '%s\\n' \"$PORTAL_OUTBOX_ENV_FILE\" > \"$FAKE_OUTBOX_ENV_LOG\"; fi ;;\n"
        "  *'run --rm database-policy') "
        "if [ -n \"${FAKE_POLICY_STATE:-}\" ]; then : > \"$FAKE_POLICY_STATE\"; fi ;;\n"
        f"  *'run --rm preflight'*) {failure} ;;\n"
        "esac\n"
        "exit 0\n"
    )
    executable.chmod(0o755)
    return executable


def test_rollback_preflights_candidate_before_replacing_services(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    outbox_environment_log = tmp_path / "outbox-environment.log"
    environment["FAKE_OUTBOX_ENV_LOG"] = str(outbox_environment_log)

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "rollback"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert calls
    assert all(f"@sha256:{'b' * 64}|" in call for call in calls)
    preflight_index = next(
        index for index, call in enumerate(calls) if "run --rm preflight" in call
    )
    replace_index = next(index for index, call in enumerate(calls) if " up --detach" in call)
    assert preflight_index < replace_index
    assert outbox_environment_log.read_text().strip() == environment["PORTAL_OUTBOX_ENV_FILE"]


def test_rollback_preflight_failure_leaves_running_services_untouched(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=True)
    environment = rollback_environment(tmp_path, fake_docker)

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "rollback"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 23
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert any("run --rm preflight" in call for call in calls)
    assert not any(" up --detach" in call for call in calls)


def test_rollback_supplies_legacy_worker_environment_only_when_required(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    outbox_environment_log = tmp_path / "outbox-environment.log"
    environment["FAKE_LEGACY_OUTBOX_IMAGE"] = "true"
    environment["FAKE_OUTBOX_ENV_LOG"] = str(outbox_environment_log)
    environment["PORTAL_LEGACY_STAFF_ASSERTION_PUBLIC_KEY"] = "legacy-public-key"

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "rollback"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "predates isolated outbox settings and assertion keyrings" in result.stderr
    assert outbox_environment_log.read_text().strip() == environment["PORTAL_ENV_FILE"]


def test_rollback_requires_a_legacy_assertion_key_for_an_old_image(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["FAKE_LEGACY_OUTBOX_IMAGE"] = "true"

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "rollback"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "PORTAL_LEGACY_STAFF_ASSERTION_PUBLIC_KEY is required" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any("run --rm preflight" in call for call in calls)
    assert not any(" up --detach" in call for call in calls)


def test_rollback_aborts_when_worker_capability_cannot_be_inspected(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["FAKE_OUTBOX_PROBE_FAILURE"] = "true"

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "rollback"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 23
    assert "Could not inspect rollback image" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any(" up --detach" in call for call in calls)


def test_rollback_rejects_a_worker_database_mismatch(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["FAKE_WORKER_DATABASE_PROBE"] = (
        "31|32|34|" + "d" * 64 + "|tls|safe"
    )

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "rollback"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "different database targets or roles" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any(" up --detach" in call for call in calls)


def test_database_policy_mismatch_fails_before_database_mutation(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "apply-db-policy"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "does not match the policy packaged in PORTAL_IMAGE" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert any("deployment-probe database-artifacts-sha256" in call for call in calls)
    assert not any(call.endswith("run --rm database-policy") for call in calls)


@pytest.mark.parametrize("command", ("apply-db-policy", "deploy"))
def test_database_policy_restores_connect_before_restricted_probes(
    tmp_path: Path,
    command: str,
) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    policy = (
        REPOSITORY_ROOT
        / "carlos_patient_portal"
        / "deploy"
        / "postgresql-audit-roles.sql"
    ).read_bytes()
    identity = (
        REPOSITORY_ROOT
        / "carlos_patient_portal"
        / "deploy"
        / "postgresql-database-identity.sql"
    ).read_bytes()
    owner_digest = sha256(b"portal_schema_owner").hexdigest()
    runtime_digest = sha256(b"portal_runtime").hexdigest()
    maintenance_digest = sha256(b"portal_audit_maintenance").hexdigest()
    database_prefix = "31|32|33"
    environment.update(
        {
            "FAKE_ARTIFACT_OUTPUT": (
                f"{sha256(policy).hexdigest()}|{sha256(identity).hexdigest()}"
            ),
            "FAKE_ADMIN_DATABASE_PROBE": (
                f"{database_prefix}|direct|tls|safe|{owner_digest}|"
                f"{runtime_digest}|{maintenance_digest}"
            ),
            "FAKE_MIGRATION_DATABASE_PROBE": (
                f"{database_prefix}|{owner_digest}|tls|safe"
            ),
            "FAKE_WEB_DATABASE_PROBE": (
                f"{database_prefix}|{runtime_digest}|tls|safe"
            ),
            "FAKE_WORKER_DATABASE_PROBE": (
                f"{database_prefix}|{runtime_digest}|tls|safe"
            ),
            "FAKE_MAINTENANCE_DATABASE_PROBE": (
                f"{database_prefix}|{maintenance_digest}|tls|safe"
            ),
            "FAKE_REQUIRE_POLICY_FIRST": "true",
            "FAKE_POLICY_STATE": str(tmp_path / "policy-applied"),
        }
    )

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), command],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    policy_index = next(
        index for index, call in enumerate(calls) if call.endswith("run --rm database-policy")
    )
    runtime_index = next(
        index
        for index, call in enumerate(calls)
        if call.endswith("deployment-probe runtime")
    )
    assert policy_index < runtime_index


def test_deploy_rejects_mismatched_web_and_worker_configuration(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["FAKE_WORKER_OUTBOX_DIGEST"] = "d" * 64

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "deploy"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "disagree on shared branding/encryption/reset settings" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any(call.endswith("run --rm migrate") for call in calls)


def test_preflight_rejects_mismatched_web_and_worker_configuration(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["FAKE_WORKER_OUTBOX_DIGEST"] = "d" * 64

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "preflight"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "disagree on shared branding/encryption/reset settings" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any(call.endswith("run --rm preflight") for call in calls)


def test_preflight_rejects_a_worker_database_mismatch(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["FAKE_WORKER_DATABASE_PROBE"] = (
        "31|32|34|" + "d" * 64 + "|tls|safe"
    )

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "preflight"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "different database targets or roles" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any(call.endswith("run --rm preflight") for call in calls)


@pytest.mark.parametrize(
    ("command", "mutation_suffix"),
    (
        ("apply-db-policy", "run --rm database-policy"),
        ("migrate", "run --rm migrate"),
        ("prune-audit", "run --rm audit-maintenance prune-audit"),
    ),
)
def test_database_identity_artifact_mismatch_fails_before_database_mutation(
    tmp_path: Path,
    command: str,
    mutation_suffix: str,
) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    policy = (
        REPOSITORY_ROOT
        / "carlos_patient_portal"
        / "deploy"
        / "postgresql-audit-roles.sql"
    ).read_bytes()
    environment["FAKE_ARTIFACT_OUTPUT"] = f"{sha256(policy).hexdigest()}|{'0' * 64}"

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), command],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "identity query does not match the query packaged" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any(call.endswith(mutation_suffix) for call in calls)


@pytest.mark.parametrize(
    "proxy_cidr",
    (
        "192.0.2.10/128",
        "2001:db8::/32",
        "deadbeef/32",
    ),
)
def test_validate_rejects_a_proxy_cidr_that_is_not_one_exact_host(
    tmp_path: Path,
    proxy_cidr: str,
) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["PORTAL_TRUSTED_PROXY_CIDR"] = proxy_cidr

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "validate"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "must" in result.stderr
    assert not Path(environment["FAKE_DOCKER_LOG"]).exists()


@pytest.mark.parametrize("proxy_cidr", ("192.0.2.10/32", "2001:db8::1/128"))
def test_validate_accepts_an_exact_proxy_host_cidr(
    tmp_path: Path,
    proxy_cidr: str,
) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)
    environment["PORTAL_TRUSTED_PROXY_CIDR"] = proxy_cidr

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), "validate"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "config --quiet" in Path(environment["FAKE_DOCKER_LOG"]).read_text()


@pytest.mark.parametrize(
    "arguments",
    (
        ("deploy", "unexpected"),
        ("export-audit", "0", "100", "unexpected"),
        ("cleanup-auth", "30", "unexpected"),
    ),
)
def test_deploy_script_rejects_unexpected_arguments_before_running_docker(
    tmp_path: Path,
    arguments: tuple[str, ...],
) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)

    result = subprocess.run(  # noqa: S603
        [str(DEPLOY_SCRIPT), *arguments],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert not Path(environment["FAKE_DOCKER_LOG"]).exists()
