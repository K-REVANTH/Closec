import os
from packages.files.dpkg import scan_dpkg_status
from packages.files.apk import scan_apk_installed
# from packages.files.rpm import scan_rpm_packages
from packages.files.python_packages import find_python_folders, scan_python_packages

dir_packages = {}

def Scan_Dir(directory):
    #if file exists scan
    if os.path.exists(f"{directory}/var/lib/dpkg/status"):
        scan_dpkg_status(f"{directory}/var/lib/dpkg/status")

    if os.path.exists(f"{directory}/lib/apk/db/installed"):
        scan_apk_installed(f"{directory}/lib/apk/db/installed")

    if find_python_folders(directory):
        scan_python_packages(directory)

    

    # if os.path.exists(f"{directory}/var/lib/rpm/Packages"):
    #     scan_rpm_packages(f"{directory}/var/lib/rpm/Packages")

    # if os.path.exists(f"{directory}/usr/lib/python/site-packages"):
    #     print(f"{directory}/usr/lib/python/site-packages")
    #     # print file content
    #     # with open(f"{directory}/var/lib/dpkg/status", 'r') as f:
    #     #     print(f.read())