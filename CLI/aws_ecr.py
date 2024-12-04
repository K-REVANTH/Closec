import json
import requests
import platform
import os
import logging
import boto3
from packages.docker.extract import Extract
from packages.docker.sbom import add_sbom, get_sbom
from packages.docker.image_info import gen_image_info
from packages.docker.query import scan_vuln

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_auth_token_ecr(region, repository):
    """Retrieve the Docker authentication token for AWS ECR."""
    print("-------------------")
    try:
        ecr_client = boto3.client('ecr', region_name=region)
        response = ecr_client.get_authorization_token()
        print("-----",ecr_client)
        auth_data = response['authorizationData'][0]
        token = auth_data['authorizationToken']
        registry = auth_data['proxyEndpoint']
        return token, registry  
    except Exception as e:
        logger.error(f"Failed to get ECR auth token: {e}")
        raise

def fetch_json(url, headers):
    """Fetch JSON data from a given URL with the provided headers."""
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.error(f"Failed to fetch JSON from {url}: {e}")
        raise

def download_image(layer_digest, headers, registry, repository_name, image_name, image_tag):
    """Download a Docker image layer and save it to a file."""
    try:
        layer_url = f"{registry}/v2/{repository_name}/blobs/{layer_digest}"
        layer_response = requests.get(layer_url, headers=headers, stream=True)
        layer_response.raise_for_status()

        images_dir = "images"
        os.makedirs(images_dir, exist_ok=True)
        layer_filename = os.path.join(images_dir, f"{image_name}_{image_tag}.tar")

        with open(layer_filename, 'wb') as f:
            for chunk in layer_response.iter_content(chunk_size=8192):
                f.write(chunk)

        logger.info(f"Layer {layer_digest} downloaded as {layer_filename}.")
    except requests.RequestException as e:
        logger.error(f"Failed to download image layer {layer_digest}: {e}")
        raise
    except IOError as e:
        logger.error(f"Failed to save image layer {layer_digest}: {e}")
        raise

def docker_img(image, region):
    """Process Docker image from ECR."""
    global image_id, image_name, image_tag, repository_name, registry

    parts = image.split('/')
    repository_name = '/'.join(parts[1:])
    image_id = parts[-1]
    image_name, image_tag = image_id.split(':')

    add_sbom("Image", image_id)

    logger.info(f"Pulling {image_id} from ECR...")

    arch = platform.machine().lower()

    # Token for authentication
    try:
        token, registry = get_auth_token_ecr(region, repository_name)
        registry = registry.replace("https://", "")
    except Exception as e:
        logger.error(f"Failed to get ECR authentication token: {e}")
        return

    # Headers for requests
    headers = {
        'Authorization': f"Basic {token}",
        'Accept': 'application/vnd.docker.distribution.manifest.list.v2+json,'
                  'application/vnd.docker.distribution.manifest.v2+json,'
                  'application/vnd.oci.image.index.v1+json,'
                  'application/vnd.oci.image.manifest.v1+json'
    }

    # Fetch manifest index
    manifest_url = f"https://{registry}/v2/{repository_name}/manifests/{image_tag}"
    try:
        manifest_data = fetch_json(manifest_url, headers)
    except Exception as e:
        logger.error(f"Failed to fetch manifest data: {e}")
        return

    valid_architectures = {m['platform']['architecture'] for m in manifest_data['manifests']}
    image_arch = arch if arch in valid_architectures else 'amd64'

    selected_manifest = next((m for m in manifest_data['manifests'] if m['platform']['architecture'] == image_arch), None)

    if not selected_manifest:
        logger.error(f"No manifest found for architecture: {image_arch}.")
        return
    
    manifest_digest = selected_manifest['digest']
    specific_manifest_url = f"https://{registry}/v2/{repository_name}/manifests/{manifest_digest}"

    try:
        specific_manifest = fetch_json(specific_manifest_url, headers)
    except Exception as e:
        logger.error(f"Failed to fetch specific manifest: {e}")
        return

    image_layer = specific_manifest.get('layers', [])
    if image_layer:
        download_image(image_layer[-1]['digest'], headers, registry, repository_name, image_name, image_tag)
    else:
        logger.error("No layers found in specific manifest.")
        return

    config_url = f"https://{registry}/v2/{repository_name}/blobs/{specific_manifest['config']['digest']}"
    try:
        config = fetch_json(config_url, headers)
    except Exception as e:
        logger.error(f"Failed to fetch image config: {e}")
        return

    # Scan the image with metadata
    image_info = gen_image_info(config)
    add_sbom('Image_Info', image_info)

    # Extract the image
    try:
        Extract(image_id)
    except Exception as e:
        logger.error(f"Failed to extract image: {e}")
        return

    sbom = get_sbom()
    logger.info(json.dumps(sbom, indent=4))

    # Print number of packages
    logger.info(f"Total number of packages Found: {len(sbom['components']['Packages'])}")

    # Scan the extracted files
    try:
        scan_vuln(sbom)
    except Exception as e:
        logger.error(f"Failed to scan vulnerabilities: {e}")

# Example usage
if __name__ == "__main__":
    # image = input("Enter AWS ECR image URI (e.g., <account_id>.dkr.ecr.<region>.amazonaws.com/repository_name:image_tag): ")
    # region = input("Enter AWS region (e.g., us-west-2): ")
    image = "590184054593.dkr.ecr.ap-south-1.amazonaws.com/nginx:1.7.11"
    region = "ap-south-1"
    docker_img(image, region)
