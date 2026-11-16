import os
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BUILD_DIR = ROOT / "build" / "cmake"
OUTPUT_DIR = BUILD_DIR / "bin"
IS_WINDOWS = sys.platform == "win32"
SCANNER_NAME = "scanner_core.exe" if IS_WINDOWS else "scanner_core"


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    configure = ["cmake", "-S", str(ROOT), "-B", str(BUILD_DIR), "-DCMAKE_BUILD_TYPE=Release"]
    if sys.platform == "win32":
        if shutil.which("ninja"):
            configure.extend(["-G", "Ninja"])
        elif shutil.which("mingw32-make"):
            configure.extend(["-G", "MinGW Makefiles"])
    run(configure)
    run(["cmake", "--build", str(BUILD_DIR), "--config", "Release", "--parallel"])

    scanner_path = OUTPUT_DIR / SCANNER_NAME
    if not scanner_path.is_file():
        raise FileNotFoundError(f"CMake did not produce the scanner binary at {scanner_path}")

    pyinstaller = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--windowed",
        "--name",
        "ProtoSec",
        "--workpath",
        str(ROOT / "build" / "pyinstaller-work"),
        "--specpath",
        str(ROOT / "build"),
        "--distpath",
        str(ROOT / "dist"),
        "--add-binary",
        f"{scanner_path}{os.pathsep}.",
        "--add-data",
        f"{ROOT / 'assets'}{os.pathsep}assets",
        "--add-data",
        f"{ROOT / 'licenses'}{os.pathsep}licenses",
        "--paths",
        str(ROOT),
    ]

    public_key = os.environ.get("PROTOSEC_LICENSE_PUBLIC_KEY_HEX", "").strip()
    if public_key:
        key_bytes = bytes.fromhex(public_key)
        if len(key_bytes) != 32:
            raise ValueError("PROTOSEC_LICENSE_PUBLIC_KEY_HEX must contain a 32-byte Ed25519 public key.")
        key_path = ROOT / "build" / "license_public_key.hex"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_text(public_key.lower(), encoding="ascii")
        pyinstaller.extend(["--add-data", f"{key_path}{os.pathsep}."])

    pyinstaller.append(str(ROOT / "src" / "gui.py"))
    run(pyinstaller)
    distribution_dir = ROOT / "dist"
    shutil.copytree(ROOT / "assets", distribution_dir / "assets", dirs_exist_ok=True)
    shutil.copytree(ROOT / "licenses", distribution_dir / "licenses", dirs_exist_ok=True)
    print(f"ProtoSec v1.0.0 packaged at {ROOT / 'dist' / ('ProtoSec.exe' if IS_WINDOWS else 'ProtoSec')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
