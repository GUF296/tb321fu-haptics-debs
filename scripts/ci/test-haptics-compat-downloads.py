#!/usr/bin/env python3
"""Compatibility downloads: retry policy and soft next-package admission."""

from __future__ import annotations

from collections import defaultdict
import hashlib
import http.server
import json
import os
import pathlib
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time


SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
DOWNLOADER = SCRIPT_DIR / "download-haptics-compat-packages.sh"
PAYLOAD = b"tb321fu-compat-download-fixture\n"


class FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.counts: defaultdict[str, int] = defaultdict(int)
        self.connection_attempts = 0

    def get_request(self):
        self.connection_attempts += 1
        return super().get_request()


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        role = self.path.strip("/").split("/", 1)[0]
        self.server.counts[self.path] += 1  # type: ignore[attr-defined]
        count = self.server.counts[self.path]  # type: ignore[attr-defined]
        if role == "not-found":
            self.send_error(404)
            return
        if role == "unauthorized":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if role == "transient" and count < 3:
            self.send_response(503)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if role == "partial":
            self.send_response(200)
            self.send_header("Content-Length", str(len(PAYLOAD) + 64))
            self.end_headers()
            self.wfile.write(PAYLOAD[:8])
            self.wfile.flush()
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)

    def log_message(self, _format: str, *_arguments: object) -> None:
        return


def generate_certificate(root: pathlib.Path) -> tuple[pathlib.Path, pathlib.Path]:
    certificate = root / "fixture-cert.pem"
    key = root / "fixture-key.pem"
    result = subprocess.run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15.0,
    )
    if result.returncode:
        raise SystemExit("could not generate the loopback TLS fixture certificate")
    return certificate, key


def validate_downloader_source(source: str) -> None:
    required = (
        "soft_admission_seconds=590",
        "remaining=$((soft_admission_seconds - SECONDS))",
        '[ "$remaining" -gt 0 ]',
        "compatibility-package next-package admission budget expired",
        "--proto '=https' --proto-redir '=https'",
        "--tlsv1.2 --connect-timeout \"$connect_timeout\"",
        "--max-time \"$remaining\" --max-filesize 67108864",
        "--retry 3 --retry-delay 2 --retry-max-time \"$remaining\"",
        "--output \"$current_partial\" -- \"${urls[$index]}\"",
        "/bin/bash -p \"$verifier\" \"$current_partial\" \"$destination\"",
        "/usr/bin/rm -f -- \"$current_partial\"",
    )
    if any(source.count(token) != 1 for token in required):
        raise ValueError("compatibility downloader source contract changed")
    if "--retry-all-errors" in source or source.count("/usr/bin/curl ") != 1:
        raise ValueError("compatibility downloader retry boundary widened")


def source_mutation_oracles(source: str) -> None:
    anchors = (
        "remaining=$((soft_admission_seconds - SECONDS))",
        '[ "$remaining" -gt 0 ]',
        "--proto '=https' --proto-redir '=https'",
        "--max-time \"$remaining\" --max-filesize 67108864",
        "--retry 3 --retry-delay 2 --retry-max-time \"$remaining\"",
        "/usr/bin/rm -f -- \"$current_partial\"",
    )
    for anchor in anchors:
        mutated = source.replace(anchor, "", 1)
        if mutated == source:
            raise SystemExit("compatibility downloader mutation anchor changed")
        try:
            validate_downloader_source(mutated)
        except ValueError:
            continue
        raise SystemExit("compatibility downloader oracle accepted a hostile mutation")
    widened = source.replace("--retry 3", "--retry-all-errors --retry 3", 1)
    try:
        validate_downloader_source(widened)
    except ValueError:
        return
    raise SystemExit("compatibility downloader oracle accepted broad retries")


def write_verifier(path: pathlib.Path) -> None:
    path.write_text(
        """#!/bin/bash -p
set -euo pipefail
[ "$#" -eq 6 ]
archive=$1
destination=$2
package=$3
expected=$6
actual=$(/usr/bin/sha256sum -- "$archive" | /usr/bin/cut -d' ' -f1)
[ "$actual" = "$expected" ] || exit 42
[ "$package" != fixture-badmeta ] || exit 43
if [ -n "${HAPTICS_TEST_VERIFY_LEDGER:-}" ]; then
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$archive" "$destination" "$package" "$4" "$5" "$expected" \
    >> "$HAPTICS_TEST_VERIFY_LEDGER"
fi
/usr/bin/chmod 0644 "$archive"
/usr/bin/mv -T -- "$archive" "$destination"
if [ -n "${HAPTICS_TEST_VERIFY_DELAY:-}" ]; then
  /usr/bin/sleep "$HAPTICS_TEST_VERIFY_DELAY"
fi
""",
        encoding="ascii",
    )
    path.chmod(0o755)


def write_records(
    path: pathlib.Path,
    base_url: str,
    first_role: str,
    *,
    wrong_digest: bool = False,
    bad_metadata: bool = False,
) -> tuple[str, ...]:
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    names = []
    records = []
    for index in range(10):
        name = "fixture-badmeta" if index == 0 and bad_metadata else f"fixture-{index:02d}"
        role = first_role if index == 0 else "ok"
        record_digest = "0" * 64 if index == 0 and wrong_digest else digest
        records.append(
            f"{name}\tamd64\t1.0.{index}\t{base_url}/{role}/{index}\t{record_digest}\n"
        )
        names.append(f"{name}_1.0.{index}_amd64.deb")
    path.write_text("".join(records), encoding="ascii")
    path.chmod(0o600)
    return tuple(names)


def clean_environment(certificate: pathlib.Path | None) -> dict[str, str]:
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "HOME": "/tmp",
        "TMPDIR": "/tmp",
        "NO_PROXY": "127.0.0.1",
        "no_proxy": "127.0.0.1",
    }
    if certificate is not None:
        environment["CURL_CA_BUNDLE"] = str(certificate)
    return environment


def run_case(
    root: pathlib.Path,
    downloader: pathlib.Path,
    verifier: pathlib.Path,
    base_url: str,
    certificate: pathlib.Path | None,
    name: str,
    first_role: str,
    *,
    expected_status: int,
    wrong_digest: bool = False,
    bad_metadata: bool = False,
    verifier_delay: str | None = None,
    extra_environment: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[bytes], tuple[str, ...], float]:
    case = root / name
    public = case / "public"
    private = case / "private"
    records = case / "records.tsv"
    case.mkdir(mode=0o700)
    public.mkdir(mode=0o755)
    private.mkdir(mode=0o700)
    names = write_records(
        records,
        base_url,
        first_role,
        wrong_digest=wrong_digest,
        bad_metadata=bad_metadata,
    )
    environment = clean_environment(certificate)
    if verifier_delay is not None:
        environment["HAPTICS_TEST_VERIFY_DELAY"] = verifier_delay
    if extra_environment is not None:
        environment.update(extra_environment)
    started = time.monotonic()
    process = subprocess.Popen(
        [
            "/bin/bash",
            "-p",
            str(downloader),
            str(verifier),
            str(records),
            str(public),
            str(private),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=20.0)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=2.0)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=2.0)
        raise SystemExit(f"compatibility downloader {name} exceeded fixture deadline")
    result = subprocess.CompletedProcess(
        process.args,
        process.returncode,
        stdout,
        stderr,
    )
    elapsed = time.monotonic() - started
    if result.returncode != expected_status:
        raise SystemExit(
            f"compatibility downloader {name} status changed: "
            f"{result.returncode} stderr={result.stderr[-1024:]!r}"
        )
    partials = tuple(private.iterdir())
    if partials:
        raise SystemExit(f"compatibility downloader {name} retained partial files")
    return result, names, elapsed


def write_fake_curl(path: pathlib.Path) -> None:
    path.write_text(
        """#!/usr/bin/python3
import json
import os
import pathlib
import signal
import sys

arguments = sys.argv[1:]
ledger = pathlib.Path(os.environ["HAPTICS_TEST_CURL_LEDGER"])
with ledger.open("a", encoding="ascii") as stream:
    stream.write(json.dumps(arguments, ensure_ascii=True, separators=(",", ":")))
    stream.write("\\n")
output_index = arguments.index("--output") + 1
output = pathlib.Path(arguments[output_index])
mode = os.environ.get("HAPTICS_TEST_CURL_MODE", "success")
if mode == "passthrough":
    os.execv("/usr/bin/curl", ["/usr/bin/curl", *arguments])
if mode == "block":
    output.write_bytes(b"partial")
    pathlib.Path(os.environ["HAPTICS_TEST_CURL_READY"]).write_text(
        "ready\\n", encoding="ascii"
    )
    while True:
        signal.pause()
if mode == "retry-model" and arguments[-1].rsplit("/", 1)[-1] == os.environ["HAPTICS_TEST_RETRY_INDEX"]:
    # Model documented curl semantics; this is not a real libcurl timing test.
    limit = int(arguments[arguments.index("--max-time") + 1])
    retry_limit = int(arguments[arguments.index("--retry-max-time") + 1])
    delay = int(arguments[arguments.index("--retry-delay") + 1])
    first_end = 2
    retry_start = first_end + delay
    retry_end = retry_start + 4
    if not (first_end < limit and retry_start < retry_limit < retry_end and 4 < limit):
        raise SystemExit("fake retry did not cross the soft admission budget")
    pathlib.Path(os.environ["HAPTICS_TEST_RETRY_LEDGER"]).write_text(
        json.dumps([[0, first_end, 503], [retry_start, retry_end, 200]]) + "\\n",
        encoding="ascii",
    )
output.write_bytes(b"tb321fu-compat-download-fixture\\n")
""",
        encoding="ascii",
    )
    path.chmod(0o755)


def make_ledger_downloader(
    root: pathlib.Path, source: str, fake_curl: pathlib.Path, *, budget: int = 590
) -> pathlib.Path:
    if source.count("/usr/bin/curl ") != 1:
        raise SystemExit("compatibility downloader curl path anchor changed")
    if source.count("soft_admission_seconds=590") != 1:
        raise SystemExit("compatibility downloader budget anchor changed")
    downloader = root / f"download-ledger-{budget}.sh"
    rewritten = source.replace("/usr/bin/curl ", f"{fake_curl} ", 1)
    rewritten = rewritten.replace(
        "soft_admission_seconds=590", f"soft_admission_seconds={budget}", 1
    )
    downloader.write_text(rewritten, encoding="utf-8")
    downloader.chmod(0o755)
    return downloader


def read_curl_ledger(path: pathlib.Path) -> list[list[str]]:
    entries = []
    for raw in path.read_text(encoding="ascii").splitlines():
        value = json.loads(raw)
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise SystemExit("fake curl ledger contains a non-string argument")
        entries.append(value)
    return entries


def validate_curl_invocation(arguments: list[str], expected_url: str) -> pathlib.Path:
    expected_prefix = [
        "--disable",
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--tlsv1.2",
        "--connect-timeout",
    ]
    if arguments[: len(expected_prefix)] != expected_prefix:
        raise SystemExit("compatibility downloader fake curl prefix changed")
    remaining = int(arguments[13])
    connect_timeout = int(arguments[11])
    expected_tail = [
        "--max-time",
        str(remaining),
        "--max-filesize",
        "67108864",
        "--retry",
        "3",
        "--retry-delay",
        "2",
        "--retry-max-time",
        str(remaining),
        "--output",
        arguments[23],
        "--",
        expected_url,
    ]
    if arguments[12:] != expected_tail:
        raise SystemExit("compatibility downloader fake curl policy changed")
    if not 1 <= remaining <= 590 or connect_timeout != min(remaining, 30):
        raise SystemExit("compatibility downloader fake curl admission allowance changed")
    output = pathlib.Path(arguments[23])
    if output.suffix != ".part":
        raise SystemExit("compatibility downloader fake curl output changed")
    return output


def validate_verifier_ledger(
    path: pathlib.Path,
    case: pathlib.Path,
    base_url: str,
    curl_entries: list[list[str]],
    *,
    expected_count: int = 10,
) -> None:
    lines = path.read_text(encoding="ascii").splitlines()
    if len(lines) != expected_count or len(curl_entries) != expected_count:
        raise SystemExit("compatibility downloader ledger count changed")
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    for index, line in enumerate(lines):
        fields = line.split("\t")
        if len(fields) != 6:
            raise SystemExit("compatibility verifier ledger shape changed")
        name = f"fixture-{index:02d}"
        archive = case / "private" / f"{name}_1.0.{index}_amd64.deb.part"
        destination = case / "public" / f"{name}_1.0.{index}_amd64.deb"
        expected_fields = [
            str(archive),
            str(destination),
            name,
            f"1.0.{index}",
            "amd64",
            digest,
        ]
        if fields != expected_fields:
            raise SystemExit("compatibility verifier invocation changed")
        curl_output = validate_curl_invocation(
            curl_entries[index], f"{base_url}/ok/{index}"
        )
        if curl_output != archive:
            raise SystemExit("curl and verifier partial-file custody diverged")


def run_cancellation_case(
    root: pathlib.Path,
    downloader: pathlib.Path,
    verifier: pathlib.Path,
    base_url: str,
    curl_ledger: pathlib.Path,
    ready: pathlib.Path,
) -> None:
    case = root / "ledger-cancellation"
    public = case / "public"
    private = case / "private"
    records = case / "records.tsv"
    case.mkdir(mode=0o700)
    public.mkdir(mode=0o755)
    private.mkdir(mode=0o700)
    write_records(records, base_url, "ok")
    environment = clean_environment(None)
    environment.update(
        {
            "HAPTICS_TEST_CURL_LEDGER": str(curl_ledger),
            "HAPTICS_TEST_CURL_MODE": "block",
            "HAPTICS_TEST_CURL_READY": str(ready),
        }
    )
    process = subprocess.Popen(
        [
            "/bin/bash",
            "-p",
            str(downloader),
            str(verifier),
            str(records),
            str(public),
            str(private),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    deadline = time.monotonic() + 5.0
    while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    if not ready.exists():
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2.0)
        raise SystemExit("compatibility cancellation fixture never entered curl")
    os.killpg(process.pid, signal.SIGTERM)
    try:
        stdout, stderr = process.communicate(timeout=5.0)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate(timeout=2.0)
        raise SystemExit("compatibility downloader did not converge after cancellation")
    if process.returncode != 143:
        raise SystemExit(
            "compatibility downloader cancellation status changed: "
            f"{process.returncode} stdout={stdout[-512:]!r} stderr={stderr[-512:]!r}"
        )
    if tuple(public.iterdir()) or tuple(private.iterdir()):
        raise SystemExit("compatibility downloader retained output after cancellation")
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        pass
    else:
        raise SystemExit("compatibility downloader left a cancellation process group")


def run_fake_admission_cases(
    root: pathlib.Path, source: str, verifier: pathlib.Path, fake_curl: pathlib.Path
) -> None:
    """Exercise soft-budget boundaries without network access or wall-clock sleeps.

    Only the disposable helper copy receives a scripted SECONDS clock. The
    retry model starts at 584, retries at 588, and succeeds at 592: its active
    transfer exceeds the 590 admission point, while no individual attempt or
    retry start exceeds curl's supplied six-second allowance. Real hard phase
    termination and cgroup permissions are deliberately not asserted here.
    """
    base_url = "https://fixture.invalid"
    admission = '  remaining=$((soft_admission_seconds - SECONDS))\n'
    after_curl = '    --output "$current_partial" -- "${urls[$index]}"\n'
    after_verify = (
        '    "$name" "$version" "$architecture" "${digests[$index]}" >/dev/null\n'
    )
    for anchor in (admission, after_curl, after_verify):
        if source.count(anchor) != 1:
            raise SystemExit("compatibility soft-clock fixture anchor changed")
    for name, crossing_index, crossing_stage, expected_status in (
        ("fake-normal", None, "none", 0),
        ("fake-retry-overrun-first", 0, "curl", 124),
        ("fake-retry-overrun-last", 9, "curl", 0),
        ("fake-verifier-overrun-last", 9, "verify", 0),
    ):
        rewritten = source
        if crossing_index is not None:
            clock = (
                f'  if [ "$index" -lt {crossing_index} ]; then SECONDS=0\n'
                f'  elif [ "$index" -eq {crossing_index} ]; then SECONDS=584\n'
                '  else SECONDS=592; fi\n'
            )
            rewritten = rewritten.replace(admission, clock + admission, 1)
            completion = after_curl if crossing_stage == "curl" else after_verify
            rewritten = rewritten.replace(
                completion,
                completion
                + f'  if [ "$index" -eq {crossing_index} ]; then SECONDS=592; fi\n',
                1,
            )
        downloader = make_ledger_downloader(root, rewritten, fake_curl)
        curl_ledger = root / f"{name}-curl.jsonl"
        verify_ledger = root / f"{name}-verify.tsv"
        retry_ledger = root / f"{name}-retry.json"
        environment = {
            "HAPTICS_TEST_CURL_LEDGER": str(curl_ledger),
            "HAPTICS_TEST_VERIFY_LEDGER": str(verify_ledger),
            "HAPTICS_TEST_CURL_MODE": "retry-model" if crossing_stage == "curl" else "success",
            "HAPTICS_TEST_RETRY_INDEX": str(crossing_index),
            "HAPTICS_TEST_RETRY_LEDGER": str(retry_ledger),
        }
        result, names, _ = run_case(
            root, downloader, verifier, base_url, None, name, "ok",
            expected_status=expected_status,
            extra_environment=environment,
        )
        expected_count = 1 if expected_status else 10
        entries = read_curl_ledger(curl_ledger)
        validate_verifier_ledger(
            verify_ledger, root / name, base_url, entries,
            expected_count=expected_count,
        )
        public = tuple(sorted((root / name / "public").iterdir()))
        if (
            tuple(path.name for path in public) != names[:expected_count]
            or any(path.read_bytes() != PAYLOAD for path in public)
        ):
            raise SystemExit("compatibility soft admission changed the verified closure")
        if expected_status:
            if result.stdout or result.stderr != (
                b"compatibility-package next-package admission budget expired\n"
            ):
                raise SystemExit("compatibility next-package admission evidence changed")
        elif result.stdout != b"HAPTICS_COMPAT_PACKAGE_DOWNLOADS=PASS\n" or result.stderr:
            raise SystemExit("compatibility current-package completion evidence changed")
        if crossing_stage == "curl":
            if json.loads(retry_ledger.read_text(encoding="ascii")) != [
                [0, 2, 503], [4, 8, 200]
            ] or entries[crossing_index][13] != "6":
                raise SystemExit("compatibility in-flight retry admission model changed")


def main(*, fake_only: bool = False) -> None:
    if fake_only and os.geteuid() == 0:
        raise SystemExit("compatibility fake-only fixtures must run without root")
    source = DOWNLOADER.read_text(encoding="utf-8")
    validate_downloader_source(source)
    source_mutation_oracles(source)
    with tempfile.TemporaryDirectory(
        prefix="tb321fu-haptics-compat-download-test."
    ) as raw:
        root = pathlib.Path(raw)
        root.chmod(0o700)
        verifier = root / "verify-fixture.sh"
        write_verifier(verifier)
        fake_curl = root / "fake-curl"
        write_fake_curl(fake_curl)
        run_fake_admission_cases(root, source, verifier, fake_curl)
        if fake_only:
            print("HAPTICS_COMPAT_DOWNLOAD_FAKE_ADMISSION=PASS")
            return
        certificate, key = generate_certificate(root)
        server = FixtureServer(("127.0.0.1", 0), FixtureHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certificate, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"https://127.0.0.1:{server.server_port}"
        try:
            success, names, _ = run_case(
                root,
                DOWNLOADER,
                verifier,
                base_url,
                certificate,
                "success",
                "ok",
                expected_status=0,
            )
            public = root / "success/public"
            if (
                success.stdout != b"HAPTICS_COMPAT_PACKAGE_DOWNLOADS=PASS\n"
                or tuple(sorted(path.name for path in public.iterdir())) != names
                or any(path.read_bytes() != PAYLOAD for path in public.iterdir())
            ):
                raise SystemExit("compatibility downloader successful closure changed")

            transient, transient_names, _ = run_case(
                root,
                DOWNLOADER,
                verifier,
                base_url,
                certificate,
                "transient",
                "transient",
                expected_status=0,
            )
            transient_path = "/transient/0"
            if (
                transient.stdout != b"HAPTICS_COMPAT_PACKAGE_DOWNLOADS=PASS\n"
                or server.counts[transient_path] != 3
                or tuple(
                    sorted(path.name for path in (root / "transient/public").iterdir())
                )
                != transient_names
            ):
                raise SystemExit("compatibility downloader transient retry changed")

            for case_name, role, expected in (
                ("not-found", "not-found", 22),
                ("unauthorized", "unauthorized", 22),
            ):
                run_case(
                    root,
                    DOWNLOADER,
                    verifier,
                    base_url,
                    certificate,
                    case_name,
                    role,
                    expected_status=expected,
                )
                if server.counts[f"/{role}/0"] != 1:
                    raise SystemExit(
                        f"compatibility downloader retried permanent {case_name} failure"
                    )
                if tuple((root / case_name / "public").iterdir()):
                    raise SystemExit(
                        f"compatibility downloader published after {case_name} failure"
                    )

            tls_connections = server.connection_attempts
            run_case(
                root,
                DOWNLOADER,
                verifier,
                base_url,
                None,
                "tls-failure",
                "ok",
                expected_status=60,
            )
            if (
                server.connection_attempts - tls_connections != 1
                or tuple((root / "tls-failure/public").iterdir())
            ):
                raise SystemExit("compatibility downloader retried TLS policy failure")

            for case_name, options in (
                ("digest-failure", {"wrong_digest": True}),
                ("metadata-failure", {"bad_metadata": True}),
                ("partial-transfer", {}),
            ):
                role = "partial" if case_name == "partial-transfer" else "ok"
                expected = 18 if case_name == "partial-transfer" else (
                    42 if case_name == "digest-failure" else 43
                )
                run_case(
                    root,
                    DOWNLOADER,
                    verifier,
                    base_url,
                    certificate,
                    case_name,
                    role,
                    expected_status=expected,
                    **options,
                )
                if tuple((root / case_name / "public").iterdir()):
                    raise SystemExit(
                        f"compatibility downloader published after {case_name}"
                    )

            bounded = root / "download-soft-admission.sh"
            if source.count("soft_admission_seconds=590") != 1:
                raise SystemExit("compatibility downloader budget anchor changed")
            bounded.write_text(
                source.replace("soft_admission_seconds=590", "soft_admission_seconds=2", 1),
                encoding="utf-8",
            )
            bounded.chmod(0o755)
            _, _, elapsed = run_case(
                root,
                bounded,
                verifier,
                base_url,
                certificate,
                "next-package-admission",
                "ok",
                expected_status=124,
                verifier_delay="3",
            )
            admission_public = tuple((root / "next-package-admission/public").iterdir())
            if elapsed < 2.5 or elapsed >= 10.0 or len(admission_public) != 1:
                raise SystemExit("compatibility downloader next-package admission changed")

            ledger_downloader = make_ledger_downloader(root, source, fake_curl)
            ledger_curl = root / "fake-curl-success.jsonl"
            ledger_verify = root / "fake-verifier-success.tsv"
            ledger_base = "https://fixture.invalid"
            success, _, _ = run_case(
                root,
                ledger_downloader,
                verifier,
                ledger_base,
                None,
                "ledger-success",
                "ok",
                expected_status=0,
                extra_environment={
                    "HAPTICS_TEST_CURL_LEDGER": str(ledger_curl),
                    "HAPTICS_TEST_CURL_MODE": "success",
                    "HAPTICS_TEST_VERIFY_LEDGER": str(ledger_verify),
                },
            )
            if success.stdout != b"HAPTICS_COMPAT_PACKAGE_DOWNLOADS=PASS\n":
                raise SystemExit("compatibility fake-ledger success marker changed")
            validate_verifier_ledger(
                ledger_verify,
                root / "ledger-success",
                ledger_base,
                read_curl_ledger(ledger_curl),
            )

            server.counts["/transient/0"] = 0
            transient_ledger = root / "ledger-transient.jsonl"
            run_case(
                root,
                ledger_downloader,
                verifier,
                base_url,
                certificate,
                "ledger-transient",
                "transient",
                expected_status=0,
                extra_environment={
                    "HAPTICS_TEST_CURL_LEDGER": str(transient_ledger),
                    "HAPTICS_TEST_CURL_MODE": "passthrough",
                },
            )
            transient_entries = read_curl_ledger(transient_ledger)
            if (
                len(transient_entries) != 10
                or server.counts["/transient/0"] != 3
            ):
                raise SystemExit("compatibility ledgered transient retry changed")
            validate_curl_invocation(
                transient_entries[0], f"{base_url}/transient/0"
            )

            for case_name, role, case_certificate, expected in (
                ("ledger-http", "not-found", certificate, 22),
                ("ledger-tls", "ok", None, 60),
                ("ledger-partial", "partial", certificate, 18),
            ):
                ledger = root / f"{case_name}.jsonl"
                connection_attempts = server.connection_attempts
                run_case(
                    root,
                    ledger_downloader,
                    verifier,
                    base_url,
                    case_certificate,
                    case_name,
                    role,
                    expected_status=expected,
                    extra_environment={
                        "HAPTICS_TEST_CURL_LEDGER": str(ledger),
                        "HAPTICS_TEST_CURL_MODE": "passthrough",
                    },
                )
                entries = read_curl_ledger(ledger)
                if len(entries) != 1:
                    raise SystemExit(
                        f"compatibility downloader {case_name} invocation count changed"
                    )
                validate_curl_invocation(entries[0], f"{base_url}/{role}/0")
                if (
                    case_name == "ledger-tls"
                    and server.connection_attempts - connection_attempts != 1
                ):
                    raise SystemExit("compatibility ledgered TLS retry changed")

            ledger_bounded = make_ledger_downloader(
                root, source, fake_curl, budget=2
            )
            admission_curl = root / "ledger-admission-curl.jsonl"
            admission_verify = root / "ledger-admission-verify.tsv"
            _, _, elapsed = run_case(
                root,
                ledger_bounded,
                verifier,
                ledger_base,
                None,
                "ledger-admission",
                "ok",
                expected_status=124,
                verifier_delay="3",
                extra_environment={
                    "HAPTICS_TEST_CURL_LEDGER": str(admission_curl),
                    "HAPTICS_TEST_CURL_MODE": "success",
                    "HAPTICS_TEST_VERIFY_LEDGER": str(admission_verify),
                },
            )
            if (
                elapsed < 2.5
                or elapsed >= 10.0
                or len(read_curl_ledger(admission_curl)) != 1
                or len(admission_verify.read_text(encoding="ascii").splitlines()) != 1
            ):
                raise SystemExit("compatibility fake-ledger next-package admission changed")

            cancellation_curl = root / "ledger-cancellation-curl.jsonl"
            cancellation_ready = root / "ledger-cancellation-ready"
            run_cancellation_case(
                root,
                ledger_downloader,
                verifier,
                ledger_base,
                cancellation_curl,
                cancellation_ready,
            )
            cancellation_entries = read_curl_ledger(cancellation_curl)
            if len(cancellation_entries) != 1:
                raise SystemExit("compatibility cancellation curl ledger changed")
            validate_curl_invocation(
                cancellation_entries[0], f"{ledger_base}/ok/0"
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5.0)
            if thread.is_alive():
                raise SystemExit("loopback HTTPS fixture did not stop")
    print("HAPTICS_COMPAT_DOWNLOAD_FIXTURE=PASS")


if __name__ == "__main__":
    if sys.argv[1:] == ["--fake-only"]:
        main(fake_only=True)
    elif sys.argv[1:]:
        raise SystemExit("unknown compatibility download fixture mode")
    else:
        main()
