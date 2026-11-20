#!/usr/bin/env python3
"""Non-root, bounded tests for fixture custody; no APT or cgroup operation."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import select
import signal
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch


SUPPORT = pathlib.Path(__file__).with_name("haptics-apt-fixture-support.py")
SPEC = importlib.util.spec_from_file_location("haptics_fixture_support_tested", SUPPORT)
assert SPEC is not None and SPEC.loader is not None
support = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = support
SPEC.loader.exec_module(support)


def leaves(error: BaseException) -> list[BaseException]:
    if isinstance(error, BaseExceptionGroup):
        return [leaf for child in error.exceptions for leaf in leaves(child)]
    return [error]


def descriptors() -> frozenset[int]:
    result = set()
    for path in pathlib.Path("/proc/self/fd").iterdir():
        descriptor = int(path.name)
        try:
            os.fstat(descriptor)
        except OSError:
            continue
        result.add(descriptor)
    return frozenset(result)


def python_command(source: str) -> list[str]:
    return ["/usr/bin/python3", "-I", "-B", "-c", source]


class IdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.identity = support.ProcessIdentity(12345, "6789")
        self.mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())

    def tearDown(self) -> None:
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), self.mask)

    def test_identity_is_required_validated_and_immutable(self) -> None:
        for arguments in ((1, "2"), (True, "2"), (2, ""), (2, "1x"), (2, "１２")):
            with self.assertRaises(ValueError):
                support.ProcessIdentity(*arguments)
        with self.assertRaises(AttributeError):
            self.identity.start_time = "replacement"
        with self.assertRaises(TypeError):
            support.require_identity_gone(12345, 0)

    def test_replaced_pid_never_gets_a_signal(self) -> None:
        with patch.object(support, "process_start_time", return_value="new"), patch.object(
            support.os, "pidfd_open"
        ) as opened:
            self.assertFalse(support.signal_identity(self.identity, signal.SIGKILL))
            opened.assert_not_called()

    def test_second_identity_check_closes_fd_without_signalling(self) -> None:
        with patch.object(support, "process_start_time", side_effect=["6789", "new"]), patch.object(
            support.os, "pidfd_open", return_value=123456
        ), patch.object(support.os, "fstat"), patch.object(support.os, "close") as close, patch.object(
            support.signal, "pidfd_send_signal"
        ) as sent:
            self.assertFalse(support.signal_identity(self.identity, signal.SIGKILL))
            sent.assert_not_called()
            close.assert_called_once_with(123456)

    def test_fstat_and_second_proc_failure_close_acquired_fd(self) -> None:
        for role in ("fstat", "second-proc"):
            with self.subTest(role=role):
                failure = PermissionError(role)
                proc = ["6789", failure] if role == "second-proc" else ["6789"]
                with patch.object(support, "process_start_time", side_effect=proc), patch.object(
                    support.os, "pidfd_open", return_value=123456
                ), patch.object(
                    support.os, "fstat", side_effect=failure if role == "fstat" else None
                ), patch.object(support.os, "close") as close, patch.object(
                    support.signal, "pidfd_send_signal"
                ) as sent:
                    with self.assertRaises(PermissionError) as caught:
                        support.signal_identity(self.identity, signal.SIGKILL)
                    self.assertIs(caught.exception, failure)
                    close.assert_called_once_with(123456)
                    sent.assert_not_called()

    def test_first_proc_failure_is_not_claimed_as_absence(self) -> None:
        with patch.object(support, "process_start_time", side_effect=PermissionError("proc")), patch.object(
            support.os, "pidfd_open"
        ) as opened:
            with self.assertRaises(PermissionError):
                support.signal_identity(self.identity, signal.SIGTERM)
            opened.assert_not_called()

    def test_fstat_and_close_failures_both_survive(self) -> None:
        inspect_error = PermissionError("fstat")
        close_error = OSError("close")
        with patch.object(support, "process_start_time", return_value="6789"), patch.object(
            support.os, "pidfd_open", return_value=123456
        ), patch.object(support.os, "fstat", side_effect=inspect_error), patch.object(
            support.os, "close", side_effect=close_error
        ), self.assertRaises(BaseExceptionGroup) as caught:
            support.signal_identity(self.identity, signal.SIGTERM)
        self.assertEqual(leaves(caught.exception), [inspect_error, close_error])

    def test_pending_handled_signal_runs_only_after_fd_closed(self) -> None:
        for signum, raises in (
            (signum, raises) for signum in support.HANDLED_SIGNALS for raises in (False, True)
        ):
            with self.subTest(signum=signum, raises=raises):
                events = []
                previous = signal.getsignal(signum)

                def handler(_signum, _frame):
                    events.append("handler")
                    if raises:
                        raise KeyboardInterrupt("controlled pending signal")

                def inspect_fd(_descriptor):
                    self.assertTrue(set(support.HANDLED_SIGNALS).issubset(
                        signal.pthread_sigmask(signal.SIG_BLOCK, ())
                    ))
                    events.append("fstat")
                    os.kill(os.getpid(), signum)

                signal.signal(signum, handler)
                try:
                    with patch.object(support, "process_start_time", return_value="6789"), patch.object(
                        support.os, "pidfd_open", return_value=123456
                    ), patch.object(support.os, "fstat", side_effect=inspect_fd), patch.object(
                        support.os, "close", side_effect=lambda fd: events.append("close")
                    ), patch.object(support.signal, "pidfd_send_signal"):
                        if raises:
                            with self.assertRaises(KeyboardInterrupt):
                                support.signal_identity(self.identity, signum)
                        else:
                            self.assertTrue(support.signal_identity(self.identity, signum))
                finally:
                    signal.signal(signum, previous)
                self.assertEqual(events, ["fstat", "close", "handler"])

    def test_identity_timeout_does_not_kill_the_asserted_process(self) -> None:
        with patch.object(support, "process_start_time", return_value="6789"), patch.object(
            support.signal, "pidfd_send_signal"
        ) as sent:
            with self.assertRaises(support.FixtureCleanupError):
                support.require_identity_gone(self.identity, timeout=0)
            sent.assert_not_called()


class LedgerTests(unittest.TestCase):
    def test_original_and_every_independent_failure_survive(self) -> None:
        events = []
        oracle = SystemExit("original oracle")
        proc_error = PermissionError("proc read failed")
        timeout = subprocess.TimeoutExpired("bounded fake child", 0.1)

        def callback(label, failure=None, result=None):
            def run():
                events.append(label)
                if failure is not None:
                    raise failure
                return result
            return run

        with self.assertRaises(BaseExceptionGroup) as caught:
            with support.CleanupLedger() as cleanup:
                cleanup.add("last release", callback("release"), kind="release")
                cleanup.add("timeout", callback("timeout", timeout), kind="release")
                cleanup.add("intervention", callback("intervention", result=True))
                cleanup.add("proc", callback("proc", proc_error), kind="release")
                raise oracle
        errors = leaves(caught.exception)
        self.assertEqual(events, ["proc", "intervention", "timeout", "release"])
        self.assertIs(errors[0], oracle)
        self.assertIn(proc_error, errors)
        self.assertIn(timeout, errors)
        self.assertTrue(any(isinstance(error, support.FixtureCleanupError) for error in errors))

    def test_emergency_intervention_cannot_make_pass(self) -> None:
        with self.assertRaises(BaseExceptionGroup):
            with support.CleanupLedger() as cleanup:
                cleanup.add("unexpected live child", lambda: True)
        self.assertEqual(cleanup.emergency_interventions, ["unexpected live child"])

    def test_expected_retained_is_explicit_but_does_not_ignore_errors(self) -> None:
        with support.CleanupLedger() as cleanup:
            cleanup.add("deliberately retained object", lambda: True, kind="expected-retained")
        self.assertEqual(cleanup.expected_retained, ["deliberately retained object"])
        with self.assertRaises(BaseExceptionGroup):
            with support.CleanupLedger() as failed:
                failed.add("broken expected cleanup", lambda: 1 / 0, kind="expected-retained")

    def test_intervention_callback_requires_boolean(self) -> None:
        with self.assertRaises(BaseExceptionGroup) as caught:
            with support.CleanupLedger() as cleanup:
                cleanup.add("missing intervention result", lambda: None)
        self.assertIsInstance(leaves(caught.exception)[0], TypeError)

    def test_failed_mask_does_not_skip_callbacks(self) -> None:
        events = []
        with self.assertRaises(BaseExceptionGroup):
            with patch.object(support.signal, "pthread_sigmask", side_effect=OSError("mask")):
                with support.CleanupLedger() as cleanup:
                    cleanup.add("close", lambda: events.append("closed"), kind="release")
        self.assertEqual(events, ["closed"])

    def test_post_applied_mask_restore_failure_preserves_oracle(self) -> None:
        events = []
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, ())
        original_mask = signal.pthread_sigmask
        oracle = SystemExit("oracle before cleanup")
        restoration_error = OSError("post-applied mask restore")

        def change_mask(how, mask):
            result = original_mask(how, mask)
            if how == signal.SIG_SETMASK:
                raise restoration_error
            return result

        with patch.object(support.signal, "pthread_sigmask", side_effect=change_mask), self.assertRaises(BaseExceptionGroup) as caught:
            with support.CleanupLedger() as cleanup:
                cleanup.add("resource", lambda: events.append("released"), kind="release")
                raise oracle
        self.assertEqual(events, ["released"])
        self.assertEqual(leaves(caught.exception), [oracle, restoration_error])
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), previous)

    def test_stream_close_failure_does_not_skip_other_streams(self) -> None:
        events = []
        process = Mock()
        process.stdin.close.side_effect = lambda: events.append("stdin")
        process.stdout.close.side_effect = lambda: events.append("stdout")
        process.stderr.close.side_effect = OSError("stderr close")
        with self.assertRaises(BaseExceptionGroup):
            support.close_process_streams(process)
        self.assertEqual(events, ["stdout", "stdin"])

    def test_process_reap_never_calls_communicate(self) -> None:
        identity = support.ProcessIdentity(12345, "6789")
        process = Mock(pid=identity.pid)
        process.wait.side_effect = [subprocess.TimeoutExpired("fake", 0), subprocess.TimeoutExpired("fake", 0), 0]
        process.communicate.side_effect = AssertionError("pipe EOF is not reap")
        with patch.object(support, "signal_identity", return_value=True) as sent:
            self.assertTrue(support.converge_process(process, identity, term_timeout=0, kill_timeout=0))
        self.assertEqual([call.args[1] for call in sent.call_args_list], [signal.SIGTERM, signal.SIGKILL])
        process.communicate.assert_not_called()

    def test_reap_timeout_does_not_skip_secondary_cleanup(self) -> None:
        events = []
        identity = support.ProcessIdentity(12345, "6789")
        process = Mock(pid=identity.pid)
        process.wait.side_effect = subprocess.TimeoutExpired("fake", 0)
        with patch.object(support, "signal_identity", return_value=True), self.assertRaises(BaseExceptionGroup):
            with support.CleanupLedger() as cleanup:
                cleanup.add("independent resources", lambda: events.append("released"), kind="release")
                cleanup.add("timed out process", lambda: support.converge_process(process, identity, term_timeout=0, kill_timeout=0))
        self.assertEqual(events, ["released"])

    def test_term_observation_failure_still_attempts_kill_and_reap(self) -> None:
        identity = support.ProcessIdentity(12345, "6789")
        process = Mock(pid=identity.pid)
        failure = PermissionError("TERM proc observation failed")
        process.wait.side_effect = [subprocess.TimeoutExpired("fake", 0), subprocess.TimeoutExpired("fake", 0), 0]
        with patch.object(support, "signal_identity", side_effect=[failure, True]) as sent, self.assertRaises(BaseExceptionGroup) as caught:
            support.converge_process(process, identity, term_timeout=0, kill_timeout=0)
        self.assertEqual([call.args[1] for call in sent.call_args_list], [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(process.wait.call_count, 3)
        self.assertEqual(leaves(caught.exception), [failure])


class ShortProcessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fds = descriptors()
        self.mask = signal.pthread_sigmask(signal.SIG_BLOCK, ())

    def tearDown(self) -> None:
        self.assertEqual(descriptors(), self.fds)
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, ()), self.mask)

    def test_fast_child_has_birth_identity_and_original_signal_mask(self) -> None:
        command = python_command("import signal;print(','.join(map(str,sorted(signal.pthread_sigmask(signal.SIG_BLOCK,())))))")
        with support.CleanupLedger() as cleanup:
            process, identity = support.spawn_fixture_process(
                command, cleanup=cleanup, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            process.wait(timeout=2)
            self.assertEqual(process.returncode, 0)
            expected = ",".join(map(str, sorted(self.mask))).encode() + b"\n"
            self.assertEqual(process.stdout.read(), expected)
            support.require_identity_gone(identity, timeout=0)

    def test_birth_proc_failure_rolls_back_its_waitable_direct_child(self) -> None:
        created = []
        original_popen = subprocess.Popen

        def popen(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            created.append(process)
            return process

        with patch.object(support.subprocess, "Popen", side_effect=popen), patch.object(
            support, "process_start_time", side_effect=PermissionError("birth proc failure")
        ), self.assertRaises(PermissionError):
            with support.CleanupLedger() as cleanup:
                support.spawn_fixture_process(
                    python_command("import time;time.sleep(5)"), cleanup=cleanup,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                )
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].returncode, -signal.SIGKILL)
        self.assertTrue(created[0].stdout.closed and created[0].stderr.closed)

    def test_term_resistant_child_is_killed_and_reaped(self) -> None:
        command = python_command("import os,signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);os.write(1,b'R');time.sleep(5)")
        with support.CleanupLedger() as cleanup:
            process, identity = support.spawn_fixture_process(
                command, cleanup=cleanup, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertTrue(select.select([process.stdout], [], [], 2)[0])
            self.assertEqual(process.stdout.read(1), b"R")
            began = time.monotonic()
            self.assertTrue(support.converge_process(process, identity, term_timeout=0.05, kill_timeout=1))
            self.assertLess(time.monotonic() - began, 1.5)
            self.assertEqual(process.returncode, -signal.SIGKILL)
            support.require_identity_gone(identity, timeout=0)

    def test_other_pipe_holder_cannot_delay_leader_reap(self) -> None:
        read_fd, write_fd = os.pipe()
        with os.fdopen(read_fd, "rb", buffering=0) as reader, os.fdopen(write_fd, "wb", buffering=0) as writer:
            with support.CleanupLedger() as cleanup:
                holder, holder_identity = support.spawn_fixture_process(
                    python_command("import time;time.sleep(5)"), cleanup=cleanup,
                    stdin=subprocess.DEVNULL, stdout=writer, stderr=subprocess.DEVNULL,
                )
                leader, leader_identity = support.spawn_fixture_process(
                    python_command("pass"), cleanup=cleanup,
                    stdin=subprocess.DEVNULL, stdout=writer, stderr=subprocess.DEVNULL,
                )
                leader.stdout = reader
                writer.close()
                leader.wait(timeout=2)
                self.assertEqual(select.select([reader], [], [], 0)[0], [])
                began = time.monotonic()
                self.assertFalse(support.converge_process(leader, leader_identity, term_timeout=0, kill_timeout=0))
                self.assertLess(time.monotonic() - began, 0.5)
                self.assertTrue(support.converge_process(holder, holder_identity, term_timeout=0.2, kill_timeout=1))
                support.require_identity_gone(holder_identity, timeout=0)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False).result
    if not result.wasSuccessful():
        raise SystemExit(1)
    print("HAPTICS_APT_FIXTURE_SUPPORT=PASS")
