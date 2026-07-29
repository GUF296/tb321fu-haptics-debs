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
package_lifecycle_test="$SCRIPT_DIR/test-haptics-package-lifecycle.sh"
systemd_unit_test="$SCRIPT_DIR/test-haptics-systemd-unit.sh"
dpkg_lifecycle_test="$SCRIPT_DIR/test-haptics-dpkg-lifecycle.sh"
bind_script_test="$SCRIPT_DIR/test-haptics-bind-script.sh"
kernel_sdk_contract_test="$SCRIPT_DIR/test-haptics-kernel-sdk-contract.sh"
expected_sha=31342e17cb20c73755623542fdac4fa1e185cb2b123d798f2f7b8024a630d457

fail() {
  printf 'test failure: %s\n' "$*" >&2
  exit 1
}

bash -n "$build_script" "$sdk_script" "$deb_verifier" "$provenance_test" "$deb_contract_test" \
  "$package_lifecycle_test" "$systemd_unit_test" "$dpkg_lifecycle_test" \
  "$bind_script_test" \
  "$kernel_sdk_contract_test" \
  "$SCRIPT_DIR/haptics-kernel-sdk-contract.sh" \
  "$SCRIPT_DIR/haptics-maintainer-scripts.sh"
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
  'haptics_promote_directory_no_clobber'; do
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
grep -F 'disable_work_sync(&haptics->play_work)' "$driver" >/dev/null
grep -F 'haptics->suspended || haptics->quiescing' "$driver" >/dev/null
grep -F 'if (suspend && err)' "$driver" >/dev/null
grep -F 'pm_sleep_ptr(&aw86937_y700_pm_ops)' "$driver" >/dev/null
grep -F '.shutdown = aw86937_y700_shutdown' "$driver" >/dev/null
if grep -Eq 'msleep\((duration_ms|play_ms)\)' "$driver"; then
  fail "AW86937 driver contains an uninterruptible effect-duration wait"
fi
bash "$package_lifecycle_test"
bash "$systemd_unit_test"
bash "$dpkg_lifecycle_test"
bash "$bind_script_test"
bash "$kernel_sdk_contract_test"

python3 - "$driver" <<'PY'
from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path


source = Path(sys.argv[1]).read_text()
ff_playback = source.index("static int aw86937_y700_ff_playback")
ff_lock = source.index("spin_lock_irqsave(&haptics->pending_lock, flags);", ff_playback)
ff_queue = source.index("schedule_work(&haptics->play_work);", ff_lock)
ff_unlock = source.index("spin_unlock_irqrestore(&haptics->pending_lock, flags);", ff_queue)
assert ff_lock < ff_queue < ff_unlock
quiesce = source.index("static int aw86937_y700_quiesce")
wake = source.index("wake_up_all(&haptics->play_wait);", quiesce)
disable = source.index("disable_work_sync(&haptics->play_work);", wake)
cancel = source.index("cancel_work_sync(&haptics->play_work);", wake)
stop = source.index("err = aw86937_y700_stop_locked(haptics);", cancel)
assert quiesce < wake < disable < cancel < stop
assert "static LIST_HEAD(aw86937_y700_devices)" not in source
assert "aw86937_y700_devices_lock" not in source
assert "struct list_head node;" not in source
probe_read = source.index("err = regmap_read(haptics->regmap, AW86937_PLAYCFG1_REG, &playcfg1);")
probe_warn = source.index("failed reading PLAYCFG1 register", probe_read)
probe_info = source.index("AW86937 haptics ready", probe_read)
assert probe_read < probe_warn < probe_info


@dataclass
class State:
    seq: int = 1
    suspended: bool = False
    quiescing: bool = False
    removing: bool = False
    work_disabled: bool = False

    def submit(self) -> str:
        if self.work_disabled:
            return "ENODEV"
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
        self.work_disabled |= remove
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
