import os
import subprocess
from hashlib import sha256
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).parents[1]
DEPLOY_SCRIPT = REPOSITORY_ROOT / "scripts" / "production-deploy"


def rollback_environment(tmp_path: Path, fake_docker: Path) -> dict[str, str]:
    environment_files = []
    for name in ("production.env", "migration.env", "database-admin.env", "maintenance.env"):
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
        "PORTAL_MIGRATION_ENV_FILE": str(environment_files[1]),
        "PORTAL_DATABASE_ADMIN_ENV_FILE": str(environment_files[2]),
        "PORTAL_MAINTENANCE_ENV_FILE": str(environment_files[3]),
        "PORTAL_DB_CA_FILE": str(ca_file),
        "PORTAL_DEPLOY_LOCK_FILE": str(tmp_path / "deploy.lock"),
        "FAKE_DOCKER_LOG": str(tmp_path / "docker.log"),
    }


def install_fake_docker(tmp_path: Path, *, fail_preflight: bool) -> Path:
    executable = tmp_path / "docker"
    failure = "exit 23" if fail_preflight else "exit 0"
    executable.write_text(
        "#!/bin/sh\n"
        "printf '%s|%s\\n' \"$PORTAL_IMAGE\" \"$*\" >> \"$FAKE_DOCKER_LOG\"\n"
        "case \"$*\" in\n"
        "  *'deployment-probe database-artifacts-sha256'*) "
        "printf '%s\\n' \"${FAKE_ARTIFACT_OUTPUT:-}\"; exit 0 ;;\n"
        f"  *'run --rm preflight'*) {failure} ;;\n"
        "esac\n"
        "exit 0\n"
    )
    executable.chmod(0o755)
    return executable


def test_rollback_preflights_candidate_before_replacing_services(tmp_path: Path) -> None:
    fake_docker = install_fake_docker(tmp_path, fail_preflight=False)
    environment = rollback_environment(tmp_path, fake_docker)

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


def test_database_identity_artifact_mismatch_fails_before_database_mutation(
    tmp_path: Path,
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
        [str(DEPLOY_SCRIPT), "apply-db-policy"],
        cwd=REPOSITORY_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0
    assert "identity query does not match the query packaged" in result.stderr
    calls = Path(environment["FAKE_DOCKER_LOG"]).read_text().splitlines()
    assert not any(call.endswith("run --rm database-policy") for call in calls)
