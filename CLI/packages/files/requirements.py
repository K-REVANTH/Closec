from packages.docker.sbom import add_sbom

req_info = {}
def scan_req(req_file):
    with open(req_file, "r") as f:
        reqs = f.readlines()
        for req in reqs:
            package, version = req.strip().split("==")
            req_info[package] = version
    add_sbom('Req-Packages', req_info)