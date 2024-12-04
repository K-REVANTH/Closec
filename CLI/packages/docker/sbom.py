# https://github.com/aquasecurity/trivy/blob/main/rpc/common/service.proto
# We can look at this method proto datatype

sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.3",
    "components": {}
}

def add_sbom(name, data):
    sbom["components"][name] = data

def get_sbom():
    return sbom