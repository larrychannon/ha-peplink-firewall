"""Package the custom integration for extraction into the HA config directory."""

import argparse
import json
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components" / "peplink_firewall"


def main() -> None:
    version = json.loads((COMPONENT / "manifest.json").read_text())["version"]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "dist" / f"peplink_firewall-{version}.zip",
    )
    output = parser.parse_args().output
    output.parent.mkdir(parents=True, exist_ok=True)
    files = [
        file
        for file in COMPONENT.rglob("*")
        if file.is_file() and file.suffix in {".py", ".json"} and "__pycache__" not in file.parts
    ]
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for file in sorted(files):
            archive.write(file, file.relative_to(ROOT))
    print(f"Packaged {len(files)} files: {output}")


if __name__ == "__main__":
    main()
