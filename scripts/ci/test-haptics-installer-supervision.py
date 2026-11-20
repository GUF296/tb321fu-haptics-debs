#!/usr/bin/env python3
"""Synthetic installer watchdog regressions; no package manager is executed."""
from __future__ import annotations

import hashlib
import importlib.util
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time

DIRECTORY = pathlib.Path(__file__).resolve().parent
INSTALLER = DIRECTORY / "install-haptics-build-dependencies.sh"
RUNNER = DIRECTORY / "run-haptics-apt-phase.py"


def load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


support = load("haptics_supervision_support", "haptics-apt-fixture-support.py")
fixtures = load("haptics_supervision_fixtures", "test-haptics-apt-phase.py")


def target(mode: str) -> None:
    identity = support.ProcessIdentity(os.getpid(), support.process_start_time(os.getpid()))
    if mode == "resistant":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
    record = pathlib.Path(os.environ["HAPTICS_SUPERVISION_TARGET"])
    record.write_text(f"{identity.pid} {identity.start_time}\n", encoding="ascii")
    if mode == "sentinel":
        time.sleep(0.8)
        pathlib.Path(os.environ["HAPTICS_SUPERVISION_SENTINEL"]).write_text("late\n")
        time.sleep(0.4)
        return
    time.sleep(30)


def wait_file(path: pathlib.Path, timeout: float = 4.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists() or path.stat().st_size == 0:
        if time.monotonic() >= deadline:
            raise AssertionError(f"fixture did not reach {path.name}")
        time.sleep(0.01)


def record_identity(path: pathlib.Path):
    wait_file(path)
    fields = path.read_text(encoding="ascii").split()
    if len(fields) != 2:
        raise AssertionError("invalid target birth record")
    return support.ProcessIdentity(int(fields[0]), fields[1])


def register_target(cleanup, record: pathlib.Path):
    identity = record_identity(record)
    cleanup.add("target birth identity", lambda: support.kill_identity(identity))
    return identity


def register_work(cleanup, root: pathlib.Path, work: pathlib.Path) -> None:
    def remove() -> bool:
        if not work.exists():
            return False
        # Only this exact synthetic fixture directory can be reclaimed here.
        if work.parent != root or work.is_symlink():
            raise AssertionError("work identity escaped synthetic fixture")
        import shutil
        shutil.rmtree(work)
        return True
    cleanup.add("unexpected installer work residue", remove)


def run_case(root: pathlib.Path, name: str, *, stopped: bool = False,
             cancel_gap: bool = False, exit_status: int | None = None,
             observation_fault: bool = False, hostile_wait: bool = False) -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    harness = root / f"{name}.sh"
    work = root / f"{name}.work"
    target_record = root / f"{name}.target"
    sentinel = root / f"{name}.sentinel"
    runner_record = root / f"{name}.runner"
    barrier = root / f"{name}.barrier"
    release = root / f"{name}.release"
    lifecycle_replacements = ()
    phase_replacements = []
    if stopped:
        # Exercise the production ten-second allowance unchanged: reducing it
        # here would hide the nested-grace regression this test must protect.
        timeout = "0.2"
    else:
        timeout = "8"
    publication = "  if read_apt_phase_clock; then\n"
    publish_barrier = (
        '  printf \'ready\\n\' > "$HAPTICS_SUPERVISION_BARRIER"\n'
        '  while [ ! -e "$HAPTICS_SUPERVISION_RELEASE" ]; do /usr/bin/sleep 0.01; done\n'
    )
    if exit_status is not None:
        phase_replacements.append((publication, publish_barrier + f"  exit {exit_status}\n  if read_apt_phase_clock; then\n"))
    elif observation_fault:
        phase_replacements.append((publication, publish_barrier + "  if read_apt_phase_clock; then\n"))
        phase_replacements.append((
            '    if state=$(read_process_state "$runner_pid" "$runner_start_time"); then',
            "    if state=$(/bin/false); then",
        ))
        # false=1 would falsely assert TERMINAL. Use the actual unknown code 2.
        phase_replacements[-1] = (phase_replacements[-1][0],
                                  "    if state=$( (exit 2) ); then")
    if cancel_gap:
        anchor = '    if state=$(read_process_state "$runner_pid" "$runner_start_time"); then'
        injected = (
            '    if [ ! -e "$HAPTICS_SUPERVISION_BARRIER" ]; then\n'
            '      printf \'ready\\n\' > "$HAPTICS_SUPERVISION_BARRIER"\n'
            '      while [ ! -e "$HAPTICS_SUPERVISION_RELEASE" ]; do /usr/bin/sleep 0.01; done\n'
            "    fi\n"
        )
        if hostile_wait:
            injected += '    wait "$runner_pid" || true\n'
        phase_replacements.append((anchor, injected + anchor))
    fixtures.render_installer_harness(
        source, harness, "supervisor-death-cgroup",
        lifecycle_replacements=lifecycle_replacements,
        run_phase_replacements=tuple(phase_replacements),
    )
    environment = os.environ.copy()
    environment.update({
        "HAPTICS_TEST_RUNNER_PID": str(runner_record),
        "HAPTICS_TEST_TIMEOUT_SECONDS": timeout,
        "HAPTICS_SUPERVISION_TARGET": str(target_record),
        "HAPTICS_SUPERVISION_SENTINEL": str(sentinel),
        "HAPTICS_SUPERVISION_BARRIER": str(barrier),
        "HAPTICS_SUPERVISION_RELEASE": str(release),
    })
    with support.CleanupLedger() as cleanup:
        register_work(cleanup, root, work)
        process, identity = support.spawn_fixture_process(
            ["/bin/bash", "-p", str(harness), str(RUNNER),
             "sentinel" if cancel_gap else "resistant", str(work), str(__file__)],
            cleanup=cleanup, env=environment, start_new_session=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        target_id = register_target(cleanup, target_record)
        runner_id = record_identity(runner_record)
        runner_pid = runner_id.pid
        # Register the ancestor last: LIFO cleanup must terminate the supervisor
        # before attempting to reap descendants, including a stopped runner.
        cleanup.add("runner birth identity", lambda: support.kill_identity(runner_id))
        if stopped:
            if not support.signal_identity(runner_id, signal.SIGSTOP):
                raise AssertionError("runner stop was not delivered")
            deadline = time.monotonic() + 2.0
            while True:
                fields = pathlib.Path(f"/proc/{runner_pid}/stat").read_text().rsplit(") ", 1)[1].split()
                if len(fields) < 20 or fields[19] != runner_id.start_time:
                    raise AssertionError("runner birth identity changed while waiting for stop")
                if fields[0] in ("T", "t"):
                    break
                if time.monotonic() >= deadline:
                    raise AssertionError("runner did not stop")
                time.sleep(0.01)
        if cancel_gap or exit_status is not None or observation_fault:
            wait_file(barrier)
            if cancel_gap:
                assert support.signal_identity(identity, signal.SIGTERM)
            release.write_text("release\n", encoding="ascii")
        started = time.monotonic()
        stdout, stderr = process.communicate(timeout=16.0)
        elapsed = time.monotonic() - started
        support.require_identity_gone(target_id, timeout=4.0)
        support.require_identity_gone(runner_id, timeout=4.0)
        expected = 143 if cancel_gap else (exit_status if exit_status is not None else (124 if stopped else 125))
        if process.returncode != expected or work.exists():
            raise AssertionError(f"{name} status={process.returncode} expected={expected}: {stderr[-1024:]!r}")
        if cancel_gap and sentinel.exists():
            raise AssertionError("cancelled phase executed its post-cancel sentinel")
        if cancel_gap and elapsed >= 0.8:
            raise AssertionError("cancelled phase waited for the normal target lifetime")
        if stopped and (elapsed > 14.5 or b"outer deadline exceeded" not in stderr):
            raise AssertionError("stopped runner bypassed the outer phase deadline")
        if observation_fault and b"could not authenticate" not in stderr:
            raise AssertionError("unknown observation did not fail closed")
        if exit_status is None and stdout != f"INSTALLER_PHASE_STATUS={expected}\n".encode():
            raise AssertionError("supervisor changed the public phase result")


def run_exit_signal_case(root: pathlib.Path) -> None:
    source = INSTALLER.read_text(encoding="utf-8")
    lifecycle = "work_dir=\n" + fixtures.exact_section(
        source, "work_dir=\n", "\nearly_script_path=", "cleanup signal lifecycle",
    )
    cleanup_entry = (
        "  local entry_status=$? apt_cleanup_active=1 cgroup_settled=1 process_settled=1 cleanup_failed=0\n"
    )
    lifecycle = fixtures.replace_once(
        lifecycle, cleanup_entry,
        cleanup_entry
        + '  printf \'ready\\n\' > "$HAPTICS_SUPERVISION_BARRIER"\n'
        '  while [ ! -e "$HAPTICS_SUPERVISION_RELEASE" ]; do /usr/bin/sleep 0.01; done\n',
        "cleanup first-command signal boundary",
    )
    harness = root / "exit-signal.sh"
    barrier = root / "exit-signal.barrier"
    release = root / "exit-signal.release"
    work = root / "exit-signal.work"
    harness.write_text(
        "#!/bin/bash -p\nset -euo pipefail\n" + lifecycle
        + '\nwork_dir=$1\n/usr/bin/mkdir -m 0700 -- "$work_dir"\nexit 77\n',
        encoding="utf-8",
    )
    env = os.environ.copy()
    env.update(HAPTICS_SUPERVISION_BARRIER=str(barrier),
               HAPTICS_SUPERVISION_RELEASE=str(release))
    with support.CleanupLedger() as cleanup:
        register_work(cleanup, root, work)
        process, identity = support.spawn_fixture_process(
            ["/bin/bash", "-p", str(harness), str(work)], cleanup=cleanup, env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        wait_file(barrier)
        assert support.signal_identity(identity, signal.SIGHUP)
        # Give Bash a chance to execute the first latch before a distinct signal;
        # the handler must preserve the first cancellation while cleanup runs.
        time.sleep(0.05)
        assert support.signal_identity(identity, signal.SIGTERM)
        release.write_text("release\n", encoding="ascii")
        stdout, stderr = process.communicate(timeout=4.0)
        if process.returncode != 129 or stdout or work.exists():
            raise AssertionError(f"EXIT signal interrupted cleanup: {process.returncode} {stderr!r}")


def check_fixture_cleanup_boundaries() -> None:
    from unittest import mock
    calls = []
    cgroup = fixtures.FixtureCgroup(pathlib.Path("/sys/fs/cgroup/unused"), 1, 2)
    with mock.patch.object(fixtures.os, "open", side_effect=[101, 102]), \
         mock.patch.object(fixtures.os, "fstat", side_effect=OSError("injected metadata failure")), \
         mock.patch.object(fixtures.os, "close", side_effect=lambda fd: calls.append(fd)):
        try:
            fixtures.open_fixture_cgroup(cgroup)
        except OSError:
            pass
        else:
            raise AssertionError("cgroup metadata failure was ignored")
    if calls != [102, 101]:
        raise AssertionError("cgroup failed-open rollback leaked a descriptor")
    calls.clear()
    def close(fd):
        calls.append(fd)
        if fd == 102:
            raise OSError("injected child-close failure")
    with mock.patch.object(fixtures.os, "close", side_effect=close):
        try:
            fixtures.close_fixture_cgroup(101, 102)
        except BaseExceptionGroup:
            pass
        else:
            raise AssertionError("cgroup close failure was ignored")
    if calls != [102, 101]:
        raise AssertionError("cgroup child-close failure skipped parent close")
    with mock.patch.object(fixtures, "cleanup_identity_record", side_effect=AssertionError("render preflight attempted process cleanup")):
        fixtures.validate_installer_renderers(pathlib.Path("/tmp/unused-render-preflight"))


def main() -> None:
    if os.geteuid() == 0:
        raise SystemExit("supervision regressions run unprivileged; root cgroup matrix is separate")
    before = hashlib.sha256(INSTALLER.read_bytes()).hexdigest()
    check_fixture_cleanup_boundaries()
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-supervision.") as raw:
        root = pathlib.Path(raw)
        run_case(root, "cancel-before-observe", cancel_gap=True)
        try:
            run_case(root, "hostile-live-wait", cancel_gap=True, hostile_wait=True)
        except AssertionError as error:
            if "post-cancel sentinel" not in str(error):
                raise
        else:
            raise AssertionError("live-wait mutation escaped the cancellation oracle")
        run_case(root, "stopped-runner", stopped=True)
        run_case(root, "unknown-state", observation_fault=True)
        run_case(root, "exit-natural-failure", exit_status=77)
        run_case(root, "exit-natural-success", exit_status=0)
        run_exit_signal_case(root)
        source = INSTALLER.read_text(encoding="utf-8")
        for signum in (None, signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            fixtures.run_installer_transaction_case(
                root, source, f"identity-settlement-{signum}",
                125 if signum is None else 128 + signum,
                cancel_role=None if signum is None else "identity",
                identity_settlement_failure=True,
                signum=signal.SIGTERM if signum is None else signum,
            )
        mutation = fixtures.replace_once(
            source,
            '    return "$status"\n  fi\n  apt_phase_pid=$runner_pid',
            '    apt_phase_cgroup_unsettled=0\n    return "$status"\n  fi\n  apt_phase_pid=$runner_pid',
            "unsettled latch hostile mutation",
        )
        try:
            fixtures.run_installer_transaction_case(
                root, mutation, "hostile-cleared-unsettled", 125,
                identity_settlement_failure=True,
            )
        except SystemExit as error:
            if "installer transaction hostile-cleared-unsettled changed" not in str(error):
                raise
        else:
            raise AssertionError("cleared-unsettled mutation executed audit without detection")
    if before != hashlib.sha256(INSTALLER.read_bytes()).hexdigest():
        raise AssertionError("installer changed during supervision regressions")
    print("HAPTICS_INSTALLER_SUPERVISION=PASS")


if __name__ == "__main__":
    if len(sys.argv) >= 3 and sys.argv[1] == "--fixture":
        target(sys.argv[2])
    elif len(sys.argv) != 1:
        raise SystemExit("unknown supervision fixture argument")
    else:
        main()
