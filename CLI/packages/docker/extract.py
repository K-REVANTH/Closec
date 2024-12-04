import docker, os, tarfile, json
from packages.files.scan_dir import Scan_Dir
from packages.files.secret_scan import Scan_Secrets

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def sanitize_tarinfo(tarinfo):
    # Sanitize the tarinfo name to remove or replace characters that are invalid.
    invalid_chars = '<>:"\\|?*[]-'
    for char in invalid_chars:
        tarinfo.name = tarinfo.name.replace(char, '_')
        tarinfo.name = tarinfo.name.lstrip('/')
    return tarinfo

def Extract(image_id):
    print(f"Extracting Image {image_id}...")
    images_dir = 'images'
    tar_file_name = f"{image_id.replace(':', '_')}.tar"
    tar_file_path = os.path.join(images_dir, tar_file_name)
    extracted_files_dir = f"{images_dir}/files_{image_id.replace(':', '_')}"

    with tarfile.open(tar_file_path, 'r') as tar:
        for member in tar.getmembers():
            if member.issym() or member.islnk():
                continue
            sanitized_member = sanitize_tarinfo(member)
            # print(f"Extracting {sanitized_member.name}")
            # tar.extract(sanitized_member, path=extracted_files_dir)
            try:
                tar.extract(sanitized_member, path=extracted_files_dir)
            except PermissionError as e:
                logging.warning(f"Permission Denied: - Skipping file {sanitized_member.name}")
            except Exception as e:
                logging.error(f"Failed to extract {sanitized_member.name}: {e}")


    # Scan the extracted files
    logging.info("Scanning Image for Packages...")
    Scan_Dir(extracted_files_dir)
    
    #Secret Scanning Function Call
    logging.info("Scanning Image for Secrets...")
    Scan_Secrets(extracted_files_dir)

    return "Extracted Image"