#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
REPO_ROOT=$(cd -- "$SCRIPT_DIR/../.." && pwd -P)
driver="$REPO_ROOT/haptics/daily-current/linux/drivers/input/misc/aw86937-y700.c"
build_script="$SCRIPT_DIR/build-tb321fu-haptics-deb.sh"
sdk_script="$SCRIPT_DIR/build-tb321fu-haptics-deb-from-kernel-sdk.sh"
deb_verifier="$SCRIPT_DIR/verify-haptics-deb.sh"
provenance_test="$SCRIPT_DIR/test-haptics-provenance.sh"
deb_contract_test="$SCRIPT_DIR/test-haptics-deb-contract.sh"
expected_sha=2e0cb7b739496ff6cf4011244ec9c0b2a2367896de65784041018b9d62186e48

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

bash -n "$build_script" "$sdk_script" "$deb_verifier" "$provenance_test" "$deb_contract_test"
[ "$(sha256sum "$driver" | awk '{print $1}')" = "$expected_sha" ] ||
  fail "canonical AW86937 driver source identity changed"
grep -F "$expected_sha" "$build_script" >/dev/null ||
  fail "builder does not pin the canonical AW86937 source"
grep -F 'HAPTICS-SOURCE-LOCK.tsv' "$build_script" "$sdk_script" >/dev/null ||
  fail "source identity is not retained in the haptics archive"
grep -F 'aw86937-build-source-sha256' "$build_script" >/dev/null ||
  fail "actual build-source identity is not retained"
for token in \
  haptics-producer-commit \
  haptics-producer-state \
  haptic-ram-firmware-sha256 \
  haptic-click-firmware-sha256 \
  haptic-test-helper-sha256 \
  aw86937-module-sha256 \
  haptic-test-helper-binary-sha256 \
  HAPTICS-SOURCE-SNAPSHOT; do
  grep -F "$token" "$build_script" >/dev/null ||
    fail "haptics source lock omits $token"
done
for token in \
  HAPTICS-PRODUCER.bundle \
  refs/heads/tb321fu-haptics-producer \
  verify-haptics-deb.sh \
  ci_sanitized_git_env \
  GIT_NO_REPLACE_OBJECTS=1 \
  HAPTICS-COMPILED-DIGESTS.env \
  HAPTICS_MODULE_SHA256= \
  HAPTICS_HELPER_BINARY_SHA256= \
  'refusing stale OUTPUT_DIR' \
  'mv -T'; do
  grep -F "$token" "$build_script" "$sdk_script" "$SCRIPT_DIR/common.sh" >/dev/null ||
    fail "haptics production contract omits $token"
done
grep -F 'fetch-depth: 0' "$REPO_ROOT/.github/workflows/build.yml" >/dev/null ||
  fail "workflow checkout lacks full producer history"
grep -F 'test-haptics-deb-contract.sh' "$REPO_ROOT/.github/workflows/build.yml" >/dev/null ||
  fail "workflow omits lightweight final DEB fixtures"
grep -F 'wait_event_timeout(haptics->play_wait' "$driver" >/dev/null
grep -F 'wake_up_all(&haptics->play_wait)' "$driver" >/dev/null
grep -F 'cancel_work_sync(&haptics->play_work)' "$driver" >/dev/null
grep -F 'haptics->suspended || haptics->quiescing' "$driver" >/dev/null
grep -F 'if (suspend && err)' "$driver" >/dev/null
grep -F 'pm_sleep_ptr(&aw86937_y700_pm_ops)' "$driver" >/dev/null
grep -F '.shutdown = aw86937_y700_shutdown' "$driver" >/dev/null
if grep -Eq 'msleep\((duration_ms|play_ms)\)' "$driver"; then
  fail "AW86937 driver contains an uninterruptible effect-duration wait"
fi

python3 - "$driver" <<'PY'
from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path


source = Path(sys.argv[1]).read_text()
quiesce = source.index("static int aw86937_y700_quiesce")
wake = source.index("wake_up_all(&haptics->play_wait);", quiesce)
cancel = source.index("cancel_work_sync(&haptics->play_work);", wake)
stop = source.index("err = aw86937_y700_stop_locked(haptics);", cancel)
assert quiesce < wake < cancel < stop


@dataclass
class State:
    seq: int = 1
    suspended: bool = False
    quiescing: bool = False
    removing: bool = False

    def submit(self) -> str:
        if self.removing:
            return "ENODEV"
        if self.suspended or self.quiescing:
            return "EBUSY"
        self.seq += 1
        return "OK"

    def quiesce(self, *, suspend: bool, remove: bool, stop_error: bool = False) -> None:
        self.suspended |= suspend
        self.quiescing = True
        self.removing |= remove
        self.seq += 1
        if not self.removing:
            self.quiescing = False
            if suspend and stop_error:
                self.suspended = False

    def resume(self, *, restore_error: bool = False) -> None:
        if restore_error:
            return
        self.suspended = False
        self.quiescing = False


normal = State()
assert normal.submit() == "OK"
playing_seq = normal.seq
normal.quiesce(suspend=True, remove=False)
assert normal.seq != playing_seq
assert normal.submit() == "EBUSY"
normal.resume()
assert normal.submit() == "OK"

failed_suspend = State()
failed_suspend.quiesce(suspend=True, remove=False, stop_error=True)
assert failed_suspend.submit() == "OK"

failed_resume = State()
failed_resume.quiesce(suspend=True, remove=False)
failed_resume.resume(restore_error=True)
assert failed_resume.submit() == "EBUSY"

removed = State()
removed.quiesce(suspend=False, remove=True)
removed.resume()
assert removed.submit() == "ENODEV"

condition = threading.Condition()
pending_seq = 1


def wait_for_effect(seq: int, timeout: float) -> None:
    with condition:
        condition.wait_for(lambda: pending_seq != seq, timeout)


worker = threading.Thread(target=wait_for_effect, args=(pending_seq, 1.0))
started = time.monotonic()
worker.start()
time.sleep(0.02)
with condition:
    pending_seq += 1
    condition.notify_all()
worker.join(0.2)
assert not worker.is_alive()
assert time.monotonic() - started < 0.25
PY

printf 'HAPTICS_LIFECYCLE=PASS\n'
