"""Build a source installer bundle from tracked files, never from a live workdir."""
from pathlib import Path
import argparse
import hashlib
import io
import json
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(output):
    import tomllib
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    subprocess.run(["python", str(ROOT / "scripts/check_release.py")], check=True, cwd=ROOT)
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT)
    if status.strip():
        raise SystemExit("请先提交已追踪文件的修改，再生成发布补丁包")
    archive = subprocess.check_output(["git", "archive", "--format=tar", "HEAD"], cwd=ROOT)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as source:
        for item in source.getmembers():
            if item.isfile():
                files[item.name] = source.extractfile(item).read()
    files["MANIFEST.sha256.json"] = (json.dumps(
        {p: hashlib.sha256(v).hexdigest() for p, v in files.items()},
        ensure_ascii=False, indent=2) + "\n").encode()
    folder_name = "qwenpaw-sidecar-patch-" + version
    output.mkdir(parents=True, exist_ok=True)
    zip_path = output / (folder_name + ".zip")
    tar_path = output / (folder_name + ".tar.gz")
    if zip_path.exists() or tar_path.exists():
        raise SystemExit("发布文件已存在，请用新的输出目录，避免覆盖旧包")
    with zipfile.ZipFile(zip_path, "x", zipfile.ZIP_DEFLATED) as z:
        for relative, data in sorted(files.items()):
            info = zipfile.ZipInfo(folder_name + "/" + relative)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100755 if relative.endswith(".sh") else 0o100644) << 16
            z.writestr(info, data)
    with tarfile.open(tar_path, "w:gz") as tar:
        for relative, data in sorted(files.items()):
            info = tarfile.TarInfo(folder_name + "/" + relative)
            info.size = len(data)
            info.mode = 0o755 if relative.endswith(".sh") else 0o644
            tar.addfile(info, io.BytesIO(data))
    checksums = output / (folder_name + "-SHA256SUMS.txt")
    checksums.write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name + "\n"
                                 for p in (zip_path, tar_path)), encoding="utf-8")
    print(zip_path)
    print(tar_path)
    print(checksums)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "dist")
    build(parser.parse_args().output.resolve())
