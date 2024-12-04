import os, re
from packages.docker.sbom import add_sbom

packages = {}

def find_python_folders(root_dir):
    python_dirs = []
    for dirpath, dirnames, _ in os.walk(root_dir):
        for dirname in dirnames:
            if dirname.startswith('python') and re.match(r'python\d+\.\d+', dirname):
                python_dirs.append(os.path.join(dirpath, dirname))
    print("Python directories found:", python_dirs)
    return python_dirs

def process_egg_info(name):
    # Assuming the folder name format is 'package_name-version-pyX.Y.egg_info'
    parts = name.split('_')
    package_name = None
    version = None

    if len(parts) == 5:
        package_name = '-'.join(parts[:-3])  # Join all but last two parts
        version = parts[2]  # The version is the second last part
    elif len(parts) == 4:
        package_name = parts[0]  # Join all but last two parts
        version = parts[1]
    packages[package_name] = version
    print(package_name, version)

def scan_python_packages(root_dir):
    python_dirs = find_python_folders(root_dir)
    if not python_dirs:
        # print("No Python directories found.")
        return None

    for python_dir in python_dirs:
        # Define site_packages_dir and check its existence
        site_packages_dir = os.path.join(python_dir, 'site_packages')
        if not os.path.exists(site_packages_dir):
            # print(f"Site packages directory does not exist: {site_packages_dir}")
            continue
        
        # print(f"Scanning {site_packages_dir} for egg-info files...")
        for dirpath, dirnames, filenames in os.walk(site_packages_dir):
            for dirname in dirnames:
                if dirname.endswith('egg_info'):
                    # print("d-----------", dirname)
                    process_egg_info(dirname)

                if dirname.endswith('dist_info'):
                    print(dirname)
                    parts = dirname.split('.dist_info')
                    package = parts[0].split('_')[0]
                    version = parts[0].split('_')[1]
                    packages[package] = version

            # Search in files
            for filename in filenames:
                if filename.endswith('egg_info'):
                    # print("f-----------", filename)
                    process_egg_info(filename)

    add_sbom('Packages', packages)