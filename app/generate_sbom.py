import json
import subprocess
import sys


def parse_freeze_output(output: str) -> list[dict]:
    packages = []
    for line in output.splitlines():
        if "==" in line:
            name, _, version = line.partition("==")
            packages.append({"name": name.strip(), "version": version.strip()})
    return packages


def main() -> None:
    result = subprocess.run(["pip", "freeze"], capture_output=True, text=True, check=True)
    json.dump(parse_freeze_output(result.stdout), sys.stdout)


if __name__ == "__main__":
    main()
