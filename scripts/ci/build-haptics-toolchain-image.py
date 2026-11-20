"""Build the pinned haptics cross toolchain inside an offline Ubuntu OCI layer."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlparse


CI = Path(__file__).resolve().parent
LOCK = CI / "HAPTICS-BUILD-PACKAGES.tsv"
BASE_URL = "https://snapshot.ubuntu.com/ubuntu/20260913T000000Z/"
BASE_IMAGE = "docker.io/library/ubuntu@sha256:496754492fb28b4d3049432f2ca787449331e23fb14f0dd3fffea86bf5a93eb4"
KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
KEYRING_SHA256 = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31"
IMAGE_CI_FILES = (
    LOCK.name, "HAPTICS-BUILD-TOOLS-REFERENCE.tsv", "HAPTICS-RELEASE-REFERENCE.tsv",
    "common.sh", "haptics-build-environment.sh", "verify-haptics-build-packages.py",
    "verify-haptics-release-reference.py", "verify-haptics-live-build-tools.sh",
    "provision-haptics-toolchain-image.sh",
)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def signed_indexes(private):
    source = private / "sources.list"
    lists = private / "lists"
    (lists / "partial").mkdir(parents=True)
    empty = private / "unused"
    empty.mkdir()
    cfg = private / "apt.conf"
    cfg.write_text(f'Dir::Etc::parts "{empty}";\nDir::Etc::main "/dev/null";\n')
    sources = [f"deb [arch=amd64 signed-by={KEYRING}] {BASE_URL} {suite} main\n"
               for suite in ("noble", "noble-updates", "noble-security")]
    source.write_text("".join(sources))
    options = ["-o",f"Dir::Etc::sourcelist={source}","-o",f"Dir::Etc::sourceparts={empty}",
               "-o",f"Dir::State::lists={lists}","-o","Dir::State::status=/dev/null",
               "-o","Dir::Cache::pkgcache=","-o","Dir::Cache::srcpkgcache=",
               "-o","Acquire::Languages=none","-o","Acquire::Check-Valid-Until=false",
               "-o","Acquire::Retries=2","-o","Acquire::https::Timeout=20",
               "-o","APT::Update::Error-Mode=any"]
    env = {**os.environ,"LC_ALL":"C","APT_CONFIG":str(cfg)}
    subprocess.run(["/usr/bin/apt-get",*options,"update"],env=env,check=True,timeout=360)
    return options,env


def package_requests(private):
    subprocess.run([sys.executable,"-IB",CI/"verify-haptics-build-packages.py",LOCK],check=True)
    if sha256(KEYRING) != KEYRING_SHA256:
        raise ValueError("Ubuntu archive trust anchor digest differs")
    rows = [r for line in LOCK.read_text().splitlines() if (r:=line.split("\t"))[0] in ("package","compat-package")]
    regular = [r for r in rows if r[0]=="package"]
    if len(regular)!=201 or len(rows)!=211:
        raise ValueError("incomplete build package closure")
    options,env = signed_indexes(private)
    index = subprocess.check_output(["/usr/bin/apt-cache",*options,"show",*[r[1] for r in regular]],text=True,env=env,timeout=120)
    records = {}
    for paragraph in index.split("\n\n"):
        fields = dict(s.split(": ",1) for s in paragraph.splitlines() if not s.startswith(" ") and ": " in s)
        pool = fields.get("Filename","")
        if not pool.startswith("pool/main/"):
            continue
        identity = (fields["Package"],fields["Architecture"],fields["Version"])
        result = (BASE_URL+pool,fields["SHA256"],int(fields["Size"]))
        if identity in records and records[identity]!=result:
            raise ValueError(f"inconsistent signed records for {identity}")
        records[identity] = result
    for kind,name,arch,version,_,*compat in rows:
        if kind=="package":
            url,digest,size = records[name,arch,version]
        else:
            url,digest = compat
            size = None
        if urlparse(url).hostname != "snapshot.ubuntu.com" or not re.fullmatch("[0-9a-f]{64}",digest):
            raise ValueError(f"invalid download record for {name}")
        yield name,arch,version,url,digest,size


def fetch(item, directory):
    name,arch,version,url,digest,size = item
    path = directory/(name+"_"+arch+".deb")
    subprocess.run(["/usr/bin/curl","--fail","--silent","--show-error","--location",
                    "--proto","=https","--proto-redir","=https","--retry","4","--retry-all-errors","--retry-delay","2",
                    "--connect-timeout","12","--max-time","180","--max-filesize",str(size or 128*1024*1024),
                    "--output",path,"--",url],check=True,timeout=750)
    if (size is not None and path.stat().st_size!=size) or sha256(path)!=digest:
        raise ValueError(f"package size or checksum differs for {name}")
    fields = subprocess.check_output(["/usr/bin/dpkg-deb","-f",path,"Package","Version","Architecture"],text=True)
    if fields!=f"Package: {name}\nVersion: {version}\nArchitecture: {arch}\n":
        raise ValueError(f"package identity differs for {name}")


def main():
    if len(sys.argv)!=2:
        raise SystemExit("usage: build-haptics-toolchain-image.sh NEW_IMAGE_ID_FILE")
    output = Path(sys.argv[1]).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    with tempfile.TemporaryDirectory(prefix=".haptics-oci-",dir=output.parent) as temp:
        private = Path(temp)
        context = private/"context"
        directory = context/"debs"
        directory.mkdir(parents=True)
        policy = context/"ci"
        policy.mkdir()
        for filename in IMAGE_CI_FILES:
            shutil.copyfile(CI/filename,policy/filename)
        requests = list(package_requests(private))
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(lambda item: fetch(item,directory), requests))
        daemon = "/usr/bin/docker"
        subprocess.run([daemon,"pull","--platform","linux/amd64",BASE_IMAGE],check=True)
        container = subprocess.check_output([daemon,"create","--platform","linux/amd64","--network=none",
            "--mount",f"type=bind,source={directory},target=/debs,readonly",
            "--mount",f"type=bind,source={policy},target=/policy,readonly",
            BASE_IMAGE,"/bin/bash","-p","/policy/provision-haptics-toolchain-image.sh"],text=True).strip()
        if not re.fullmatch("[0-9a-f]{64}",container):
            raise ValueError("Docker returned an invalid build container identity")
        try:
            subprocess.run([daemon,"start","--attach",container],check=True)
            status = subprocess.check_output([daemon,"wait",container],text=True).strip()
            if status!="0":
                raise RuntimeError(f"toolchain provisioning exited {status}")
            identifier = subprocess.check_output([daemon,"commit","--change",'CMD ["/bin/bash"]',container],text=True).strip()
        finally:
            subprocess.run([daemon,"rm","--force",container],check=True)
        if not re.fullmatch("sha256:[0-9a-f]{64}",identifier):
            raise ValueError("Docker build returned an invalid image ID")
        details = subprocess.check_output(["/usr/bin/docker","image","inspect","--format",
            "{{.Os}}/{{.Architecture}} {{.Id}}",identifier],text=True).strip()
        if details!="linux/amd64 "+identifier:
            raise ValueError("Docker image identity or architecture differs")
        image_id = private/"image.iid"
        image_id.write_text(identifier+"\n")
        os.link(image_id,output)
        print(f"HAPTICS_TOOLCHAIN_IMAGE=PASS {identifier}",flush=True)


if __name__=="__main__":
    main()
