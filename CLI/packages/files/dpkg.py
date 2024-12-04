from packages.docker.sbom import add_sbom

packages = {}

def scan_dpkg_status(file):
    print(f"Scanning {file}")
    with open(file, 'r') as f:
        current_package = None
        current_version = None
        current_source = None
        for line in f:
            line = line.strip()  # Remove leading/trailing whitespace
            if line.startswith("Package:"):
                # Extract package name
                current_package = line.split(":", 1)[1].strip()

            elif line.startswith("Source:"):
                # Extract source package name
                current_source = line.split(":", 1)[1].strip()
                # Ensure we have the current package version before setting the source
                if current_package and current_version:
                    packages[current_source] = current_version

            elif line.startswith("Version:"):
                # Extract version
                current_version = line.split(":", 1)[1].strip()
                # Add package name and version to the dictionary
                if current_package and current_version:
                    packages[current_package] = current_version
                    # Check if we have a source package and add it to the source_packages
                    if current_source:
                        packages[current_source] = current_version
                    # Reset for the next package
                    current_package = None
                    current_version = None
                    current_source = None

    add_sbom('Packages', packages)

