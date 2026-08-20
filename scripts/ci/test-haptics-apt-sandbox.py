#!/usr/bin/env python3
"""Root-only fixture proving compatibility archives are readable by _apt."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import pathlib
import pwd
import signal
import sys
import tempfile
import time


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
MODULE_PATH = SCRIPT_DIR / "verify-haptics-apt-transaction.py"


def load_module():
    spec = importlib.util.spec_from_file_location("haptics_apt_transaction", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise SystemExit("cannot load APT transaction verifier")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def require_rejected(verifier, callback, label: str, expected: str) -> None:
    if not expected:
        raise SystemExit(f"empty rejection boundary for hostile fixture: {label}")
    try:
        callback()
    except verifier.AptTransactionError as exc:
        if expected not in str(exc):
            raise SystemExit(
                f"_apt archive verifier rejected {label} at the wrong boundary: {exc}"
            ) from exc
        return
    except BaseException as exc:
        raise SystemExit(
            f"_apt archive verifier raised an unexpected exception for {label}: "
            f"{type(exc).__name__}: {exc}"
        ) from exc
    raise SystemExit(f"_apt archive verifier accepted hostile fixture: {label}")


def prove_rejection_oracle_does_not_swallow_unrelated_exceptions(verifier) -> None:
    for sentinel in (
        ValueError("oracle sentinel"),
        OSError("oracle sentinel"),
        SystemExit("oracle sentinel"),
    ):
        try:
            require_rejected(
                verifier,
                lambda sentinel=sentinel: (_ for _ in ()).throw(sentinel),
                "oracle sentinel",
                "must not match",
            )
        except SystemExit as exc:
            if (
                "unexpected exception" not in str(exc)
                or f"{type(sentinel).__name__}: oracle sentinel" not in str(exc)
            ):
                raise SystemExit(
                    f"_apt rejection oracle failed unclearly: {exc}"
                ) from exc
            continue
        raise SystemExit(
            f"_apt rejection oracle swallowed {type(sentinel).__name__}"
        )


def cleanup_fixture_child(child: int) -> None:
    """Signal only a child whose unreaped ownership was just re-confirmed."""
    while True:
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        if waited == child:
            return
        if waited != 0:
            raise SystemExit("fixture child cleanup returned an unexpected process")
        break
    try:
        os.kill(child, signal.SIGKILL)
    except ProcessLookupError:
        pass
    while True:
        try:
            waited, _ = os.waitpid(child, 0)
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        if waited != child:
            raise SystemExit("fixture child cleanup reaped an unexpected process")
        return


def prove_lost_fixture_child_is_never_signalled() -> None:
    original_waitpid = os.waitpid
    original_kill = os.kill
    signals: list[tuple[int, int]] = []

    def lost_child(_child: int, _options: int):
        raise ChildProcessError

    def record_signal(child: int, signum: int) -> None:
        signals.append((child, signum))

    os.waitpid = lost_child
    os.kill = record_signal
    try:
        cleanup_fixture_child(424242)
    finally:
        os.waitpid = original_waitpid
        os.kill = original_kill
    if signals:
        raise SystemExit("fixture cleanup signalled a child after ownership was lost")


def prove_fixture_child_cleanup_positive_paths() -> None:
    original_waitpid = os.waitpid
    original_kill = os.kill
    child = 424242
    signals: list[tuple[int, int]] = []
    try:
        def reaped_child(pid: int, options: int):
            if pid != child or options != os.WNOHANG:
                raise SystemExit("fixture reaped-child wait identity changed")
            return child, 0

        def record_signal(pid: int, signum: int) -> None:
            signals.append((pid, signum))

        os.waitpid = reaped_child
        os.kill = record_signal
        cleanup_fixture_child(child)
        if signals:
            raise SystemExit("fixture cleanup signalled an already reaped child")

        wait_options: list[int] = []
        results = [
            InterruptedError(),
            (0, 0),
            InterruptedError(),
            (child, 0),
        ]

        def live_child(pid: int, options: int):
            if pid != child or not results:
                raise SystemExit("fixture live-child wait identity changed")
            wait_options.append(options)
            result = results.pop(0)
            if isinstance(result, BaseException):
                raise result
            return result

        signals.clear()
        os.waitpid = live_child
        cleanup_fixture_child(child)
        if results or wait_options != [os.WNOHANG, os.WNOHANG, 0, 0]:
            raise SystemExit("fixture live-child wait/retry contract changed")
        if signals != [(child, signal.SIGKILL)]:
            raise SystemExit("fixture live-child signal identity changed")
    finally:
        os.waitpid = original_waitpid
        os.kill = original_kill


def prove_lost_verifier_child_is_never_signalled(verifier) -> None:
    original_waitpid = verifier.os.waitpid
    original_kill = verifier.os.kill
    signals: list[tuple[int, int]] = []

    def lost_child(_child: int, _options: int):
        raise ChildProcessError

    def record_signal(child: int, signum: int) -> None:
        signals.append((child, signum))

    verifier.os.waitpid = lost_child
    verifier.os.kill = record_signal
    try:
        try:
            verifier._wait_for_child(424242, 0.05)
        except ChildProcessError:
            pass
        else:
            raise SystemExit("verifier lost-child oracle did not retain its primary")
    finally:
        verifier.os.waitpid = original_waitpid
        verifier.os.kill = original_kill
    if signals:
        raise SystemExit("verifier signalled a child after ownership was lost")


def prove_verifier_cleanup_cancellation_custody(verifier) -> None:
    original_kill = verifier.os.kill
    for applied in (False, True):
        child = os.fork()
        if child == 0:
            time.sleep(30)
            os._exit(0)
        cancellation = KeyboardInterrupt(
            f"injected {'applied' if applied else 'pre-signal'} child cleanup cancellation"
        )
        primary = verifier.AptTransactionError("ordinary child cleanup primary")
        calls = 0

        def cancel_signal(pid: int, signum: int) -> None:
            nonlocal calls
            if pid == child and signum == signal.SIGKILL:
                calls += 1
                if calls == 1:
                    if applied:
                        original_kill(pid, signum)
                    raise cancellation
            original_kill(pid, signum)

        verifier.os.kill = cancel_signal
        try:
            selected = verifier.cleanup_child_after_failure(child, primary)
        finally:
            verifier.os.kill = original_kill
        if selected is not cancellation or selected.__cause__ is not primary or not calls:
            cleanup_fixture_child(child)
            raise SystemExit(
                f"verifier child cleanup changed {applied=} cancellation: {selected}"
            ) from selected
        try:
            waited, _ = os.waitpid(child, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            cleanup_fixture_child(child)
            raise SystemExit(
                f"verifier child cleanup left {applied=} custody: {waited}"
            )


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("APT sandbox fixture must run as root")
    verifier = load_module()
    prove_rejection_oracle_does_not_swallow_unrelated_exceptions(verifier)
    prove_lost_fixture_child_is_never_signalled()
    prove_fixture_child_cleanup_positive_paths()
    prove_lost_verifier_child_is_never_signalled(verifier)
    prove_verifier_cleanup_cancellation_custody(verifier)
    if not hasattr(verifier, "verify_apt_readable_archive"):
        raise SystemExit("_apt archive-readability verifier is missing")
    if not hasattr(verifier, "_wait_for_child"):
        raise SystemExit("_apt archive-readability verifier has no bounded child wait")
    hung_child = os.fork()
    if hung_child == 0:
        time.sleep(30)
        os._exit(0)
    started = time.monotonic()
    try:
        require_rejected(
            verifier,
            lambda: verifier._wait_for_child(hung_child, 0.05),
            "hung _apt archive proof child",
            "_apt archive proof timed out",
        )
        if time.monotonic() - started > 2:
            raise SystemExit("_apt child timeout exceeded its outer watchdog")
        try:
            waited, _ = os.waitpid(hung_child, os.WNOHANG)
        except ChildProcessError:
            pass
        else:
            raise SystemExit(
                f"_apt child timeout did not reap its child: waited={waited}"
            )
    finally:
        cleanup_fixture_child(hung_child)
    apt_account = pwd.getpwnam("_apt")
    with tempfile.TemporaryDirectory(prefix="tb321fu-haptics-apt-sandbox-test.") as raw:
        root = pathlib.Path(raw)
        root.chmod(0o755)
        archive = root / "compat.deb"
        payload = b"verified compatibility archive\n"
        archive.write_bytes(payload)
        archive.chmod(0o644)
        metadata = archive.stat()

        def prove_post_fork_ownership(case: str) -> None:
            original_fork = verifier.os.fork
            original_monotonic = verifier.time.monotonic
            forked_children: list[int] = []
            parent_after_fork = [False]
            interrupt_pending = [case == "cancellation"]
            started = original_monotonic()

            def owned_fork() -> int:
                child = original_fork()
                if child > 0:
                    forked_children.append(child)
                    parent_after_fork[0] = True
                return child

            def hostile_clock() -> float:
                if parent_after_fork[0]:
                    if interrupt_pending[0]:
                        interrupt_pending[0] = False
                        raise KeyboardInterrupt("injected post-fork cancellation")
                    return 1.0 + (original_monotonic() - started)
                return 0.0

            verifier.os.fork = owned_fork
            verifier.time.monotonic = hostile_clock
            caught: BaseException | None = None
            try:
                verifier.verify_apt_readable_archive(
                    archive,
                    hashlib.sha256(payload).hexdigest(),
                    metadata.st_dev,
                    metadata.st_ino,
                    apt_account.pw_uid,
                    apt_account.pw_gid,
                    deadline=1.0 if case == "deadline" else None,
                )
            except BaseException as exc:
                caught = exc
            finally:
                verifier.os.fork = original_fork
                verifier.time.monotonic = original_monotonic
            if not forked_children:
                raise SystemExit(f"post-fork {case} fixture did not create a child")
            child = forked_children[0]
            leaked = False
            try:
                waited, _ = os.waitpid(child, os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                leaked = True
                if waited == 0:
                    try:
                        os.kill(child, 9)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(child, 0)
                    except ChildProcessError:
                        pass
            if leaked:
                raise SystemExit(f"post-fork {case} left an unreaped child")
            if case == "deadline":
                if (
                    not isinstance(caught, verifier.AptTransactionError)
                    or str(caught)
                    != "APT hook verification exceeded its deadline"
                ):
                    raise SystemExit(
                        f"post-fork deadline lost its primary error: {caught}"
                    ) from caught
            elif not isinstance(caught, KeyboardInterrupt):
                raise SystemExit(
                    f"post-fork cancellation was not preserved: {caught}"
                ) from caught

        prove_post_fork_ownership("deadline")
        prove_post_fork_ownership("cancellation")

        def prove_atomic_fork_handoff(
            signum: signal.Signals,
            cancellation: BaseException,
        ) -> None:
            original_fork = verifier.os.fork
            original_mask = frozenset(
                signal.pthread_sigmask(signal.SIG_BLOCK, set())
            )
            if signum in original_mask:
                raise SystemExit(
                    f"_apt {signum.name} fork-handoff oracle inherited a blocked signal"
                )
            previous_handler = signal.getsignal(signum)
            forked_children: list[int] = []
            events: list[int] = []

            def raise_cancellation(received: int, _frame) -> None:
                events.append(received)
                raise cancellation

            def signal_at_fork_return() -> int:
                child = original_fork()
                if child > 0:
                    forked_children.append(child)
                    os.kill(os.getpid(), signum)
                return child

            signal.signal(signum, raise_cancellation)
            verifier.os.fork = signal_at_fork_return
            caught: BaseException | None = None
            try:
                verifier.verify_apt_readable_archive(
                    archive,
                    hashlib.sha256(payload).hexdigest(),
                    metadata.st_dev,
                    metadata.st_ino,
                    apt_account.pw_uid,
                    apt_account.pw_gid,
                )
            except BaseException as exc:
                caught = exc
            finally:
                verifier.os.fork = original_fork
                try:
                    signal.pthread_sigmask(signal.SIG_SETMASK, set(original_mask))
                except BaseException as exc:
                    if caught is None:
                        caught = exc
                signal.signal(signum, previous_handler)
            if (
                caught is not cancellation
                or events != [signum]
                or len(forked_children) != 1
            ):
                for child in forked_children:
                    cleanup_fixture_child(child)
                raise SystemExit(
                    f"_apt {signum.name} fork handoff lost exact cancellation: {caught}"
                ) from caught
            child = forked_children[0]
            try:
                waited, _ = os.waitpid(child, os.WNOHANG)
            except ChildProcessError:
                pass
            else:
                cleanup_fixture_child(child)
                raise SystemExit(
                    f"_apt {signum.name} fork handoff left child custody: {waited}"
                )
            if (
                frozenset(signal.pthread_sigmask(signal.SIG_BLOCK, set()))
                != original_mask
            ):
                raise SystemExit(
                    f"_apt {signum.name} fork handoff changed the caller mask"
                )

        prove_atomic_fork_handoff(
            signal.SIGINT,
            KeyboardInterrupt("injected _apt fork-handoff SIGINT"),
        )
        prove_atomic_fork_handoff(
            signal.SIGTERM,
            SystemExit("injected _apt fork-handoff SIGTERM"),
        )
        for label, apt_uid, apt_gid in (
            ("root _apt uid", 0, apt_account.pw_gid),
            ("root _apt gid", apt_account.pw_uid, 0),
        ):
            require_rejected(
                verifier,
                lambda apt_uid=apt_uid, apt_gid=apt_gid: (
                    verifier.verify_apt_readable_archive(
                        archive,
                        hashlib.sha256(payload).hexdigest(),
                        metadata.st_dev,
                        metadata.st_ino,
                        apt_uid,
                        apt_gid,
                    )
                ),
                label,
                "_apt archive proof must use a non-root identity",
            )
        verifier.verify_apt_readable_archive(
            archive,
            hashlib.sha256(payload).hexdigest(),
            metadata.st_dev,
            metadata.st_ino,
            apt_account.pw_uid,
            apt_account.pw_gid,
        )
        root.chmod(0o700)
        require_rejected(
            verifier,
            lambda: verifier.verify_apt_readable_archive(
                archive,
                hashlib.sha256(payload).hexdigest(),
                metadata.st_dev,
                metadata.st_ino,
                apt_account.pw_uid,
                apt_account.pw_gid,
            ),
            "nontraversable parent",
            "_apt could not open and hash the verified archive inode",
        )
        root.chmod(0o755)
        require_rejected(
            verifier,
            lambda: verifier.verify_apt_readable_archive(
                archive,
                "0" * 64,
                metadata.st_dev,
                metadata.st_ino,
                apt_account.pw_uid,
                apt_account.pw_gid,
            ),
            "wrong digest",
            "_apt could not open and hash the verified archive inode",
        )
        original = root / "compat.original"
        archive.rename(original)
        archive.write_bytes(payload)
        archive.chmod(0o644)
        require_rejected(
            verifier,
            lambda: verifier.verify_apt_readable_archive(
                archive,
                hashlib.sha256(payload).hexdigest(),
                metadata.st_dev,
                metadata.st_ino,
                apt_account.pw_uid,
                apt_account.pw_gid,
            ),
            "same-byte replacement inode",
            "_apt could not open and hash the verified archive inode",
        )
        archive.unlink()
        archive.symlink_to(original)
        require_rejected(
            verifier,
            lambda: verifier.verify_apt_readable_archive(
                archive,
                hashlib.sha256(payload).hexdigest(),
                original.stat().st_dev,
                original.stat().st_ino,
                apt_account.pw_uid,
                apt_account.pw_gid,
            ),
            "archive symlink",
            "_apt could not open and hash the verified archive inode",
        )
    print("HAPTICS_APT_SANDBOX_FIXTURE=PASS")


if __name__ == "__main__":
    main()
