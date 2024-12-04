import re
import os
from packages.files.secret_patterns import SECRET_PATTERNS
from packages.docker.sbom import add_sbom

def find_secrets_in_file(filepath):
    secrets_found = []
    with open(filepath, 'r', errors='ignore') as file:
        content = file.read()
        for pattern in SECRET_PATTERNS:
            matches = pattern["pattern"].findall(content)
            if matches:
                for match in matches:
                    secrets_found.append({
                        "path": filepath,
                        "name": pattern["name"],
                        "description": pattern["description"],
                        "value": match
                    })
    return secrets_found

def Scan_Secrets(directory):
    all_secrets = []
    scanned_files = set()
    for root, _, files in os.walk(directory):
        for file in files:
            filepath = os.path.join(root, file)
            if filepath not in scanned_files:
                scanned_files.add(filepath)
                secrets = find_secrets_in_file(filepath)
                all_secrets.extend(secrets)
    add_sbom('Secrets', all_secrets)
    return all_secrets

def print_secrets(secrets):
    # Dictionary to store the first occurrence of each (name, description) pair
    unique_secrets = {}
    seen_names = set()  # To track (name, description) pairs

    for secret in secrets:
        key = (secret["name"], secret["description"])
        if key not in seen_names:
            seen_names.add(key)
            unique_secrets[key] = {
                "path": secret["path"],
                "value": secret["value"]
            }

    # Print the unique secrets
    for (name, description), secret in unique_secrets.items():
        print(f"File: {secret['path']}")
        print(f"  Secret Type: {name}")
        print(f"  Description: {description}")
        print(f"  Value: {secret['value']}")
        print("-" * 40)
