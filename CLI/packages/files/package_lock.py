import json
from collections import defaultdict
from packages.docker.sbom import add_sbom

def scan_package_lock(file_path):
    # Open and load the package-lock.json file
    with open(file_path, 'r') as file:
        data = json.load(file)

    # Initialize a dictionary to store packages and their versions
    packages = defaultdict(set)

    def traverse_dependencies(deps):
        for package_name, package_info in deps.items():
            # Extract package name and version
            version = package_info.get('version')
            if version:
                formatted_name = format_package_name(package_name)
                packages[formatted_name].add(version)
            # Recurse into nested dependencies
            nested_deps = package_info.get('dependencies', {})
            if nested_deps:
                traverse_dependencies(nested_deps)

    def format_package_name(package_name):
        """Extract the final part of the package name, convert to lowercase."""
        if '/' in package_name:
            # Extract the final part of the package name after the last '/'
            package_name = package_name.split('/')[-1]
        return package_name.lower()

    # Traverse root dependencies
    root_dependencies = data.get('dependencies', {})
    traverse_dependencies(root_dependencies)

    # Traverse dev dependencies
    dev_dependencies = data.get('devDependencies', {})
    traverse_dependencies(dev_dependencies)

    # Traverse nested node_modules
    node_modules = data.get('node_modules', {})
    for module_name, module_info in node_modules.items():
        if 'version' in module_info:
            formatted_name = format_package_name(module_name)
            packages[formatted_name].add(module_info['version'])
        nested_deps = module_info.get('dependencies', {})
        if nested_deps:
            traverse_dependencies(nested_deps)

    packages_dict = {pkg: sorted(versions) for pkg, versions in packages.items()}
    npm_packages_lock = dict(sorted(packages_dict.items()))
    add_sbom("NPM-Packages", npm_packages_lock)