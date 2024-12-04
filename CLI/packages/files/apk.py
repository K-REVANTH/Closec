from packages.docker.sbom import add_sbom

packages = {}

def scan_apk_installed(file):
    print(f"Scanning {file}")
    with open(file, 'r') as f:
        current_package = None
        current_version = None
        current_origin = None
        for line in f:
            line = line.strip()
            if line.startswith("P:"):
                # Capture the package name
                current_package = line.split(":", 1)[1].strip()
            elif line.startswith("V:"):
                # Capture the version
                current_version = line.split(":", 1)[1].strip()
                if current_package and current_version:
                    # Add package and its version to the dictionary
                    packages[current_package] = current_version
            elif line.startswith("o:"):
                # Capture the origin
                current_origin = line.split(":", 1)[1].strip()
                if current_package and current_version and current_origin:
                    # Add origin with the parent version to the dictionary
                    packages[current_origin] = current_version
                    current_package = None
                    current_version = None
                    current_origin = None

    # Add the collected data to SBOM
    add_sbom('Packages', packages)
