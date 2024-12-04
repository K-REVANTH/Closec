import json
import requests
import platform
import os
import boto3
from botocore.exceptions import NoCredentialsError
from packages.docker.extract import Extract
from packages.docker.sbom import add_sbom, get_sbom
from packages.docker.image_info import gen_image_info
from packages.docker.query import scan_vuln

def get_ecr_auth_token(region):
    """Retrieve the ECR authentication token using boto3."""
    ecr_client = boto3.client('ecr', region_name=region)
    try:
        response = ecr_client.get_authorization_token()
        token = response['authorizationData'][0]['authorizationToken']
        return token
    except NoCredentialsError:
        print("AWS credentials not found or expired.")
        raise

def fetch_json(url, headers):
    """Fetch JSON data from a given URL with the provided headers."""
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def download_image(layer_digest, headers, registry, image_name, image_tag):
    """Download a Docker image layer and save it to a file."""
    layer_url = f"{registry}/v2/{image_name}/blobs/{layer_digest}"
    layer_response = requests.get(layer_url, headers=headers, stream=True)
    layer_response.raise_for_status()

    images_dir = "images"
    if not os.path.exists(images_dir):
        os.makedirs(images_dir)
    layer_filename = os.path.join(images_dir, f"{image_name}_{image_tag}.tar")
    with open(layer_filename, 'wb') as f:
        for chunk in layer_response.iter_content(chunk_size=8192):
            f.write(chunk)

def ecr_img(image, region='ap-south-1', account_id='590184054593'):
    """Pull an image from AWS ECR."""
    
    global image_name, image_tag, registry

    if '/' in image:
        parts = image.split('/')
        image_name = parts[-1].split(':')[0]
        image_tag = parts[-1].split(':')[1]
        repository_prefix = '/'.join(parts[:-1])
    else:
        repository_prefix = 'library'
        image_name = image.split(':')[0]
        image_tag = image.split(':')[1]

    registry = f"https://{account_id}.dkr.ecr.{region}.amazonaws.com"

    add_sbom("Image", image_name)

    print(f"Pulling {image_name} from ECR...")

    arch = platform.machine().lower()
    try:
        token = get_ecr_auth_token(region)
    except Exception as e:
        print(f"Failed to get auth token: {e}")
        return
    
    headers = {
        'Authorization': f"Bearer {token}",
        'Accept': 'application/vnd.docker.distribution.manifest.list.v2+json,'
                  'application/vnd.docker.distribution.manifest.v2+json,'
                  'application/vnd.oci.image.index.v1+json,'
                  'application/vnd.oci.image.manifest.v1+json'
    }

    manifest_url = f"{registry}/v2/{repository_prefix}/{image_name}/{image_tag}"
    print(manifest_url)
    try:
        manifest_data = fetch_json(manifest_url, headers)
    except Exception as e:
        print(f"Failed to fetch manifest: {e}")
        return

    valid_architectures = {m['platform']['architecture'] for m in manifest_data.get('manifests', [])}
    image_arch = arch if arch in valid_architectures else 'amd64'

    selected_manifest = next((m for m in manifest_data.get('manifests', []) if m['platform']['architecture'] == image_arch), None)

    if not selected_manifest:
        print(f"No manifest found for architecture: {image_arch}.")
        return
    
    manifest_digest = selected_manifest['digest']
    specific_manifest_url = f"{registry}/v2/{repository_prefix}/{image_name}/manifests/{manifest_digest}"

    try:
        specific_manifest = fetch_json(specific_manifest_url, headers)
    except Exception as e:
        print(f"Failed to fetch specific manifest: {e}")
        return

    image_layer = specific_manifest.get('layers', [])
    if not image_layer:
        print("No layers found in the manifest.")
        return
    
    download_image(image_layer[-1]['digest'], headers, registry, image_name)

    config_url = f"{registry}/v2/{repository_prefix}/{image_name}/blobs/{specific_manifest['config']['digest']}"
    try:
        config = fetch_json(config_url, headers)
    except Exception as e:
        print(f"Failed to fetch config: {e}")
        return

    image_info = gen_image_info(config)
    add_sbom('Image_Info', image_info)

    Extract(image_name)

    sbom = get_sbom()
    print(json.dumps(sbom, indent=4))
    
    try:
        print(f"Total number of packages Found: {len(sbom['components']['Packages'])}")
        print(f"Total number of Secrets Found: {len(sbom['components']['Secrets'])}")
    except KeyError:
        print("No Packages/Secrets found")

# Example usage
image = "nginx/nginx:1.7.11"
ecr_img(image)