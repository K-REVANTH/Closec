import json, requests, platform, os
from packages.docker.extract import Extract
from packages.docker.sbom import add_sbom, get_sbom
from packages.docker.image_info import gen_image_info
from packages.docker.query import scan_vuln

def get_auth_token():
    """Retrieve the Docker authentication token."""
    auth_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repository_prefix}/{image_name}:pull"
    response = requests.get(auth_url)
    response.raise_for_status()  
    return response.json().get('token')

def fetch_json(url, headers):
    """Fetch JSON data from a given URL with the provided headers."""
    response = requests.get(url, headers=headers)
    response.raise_for_status()  
    return response.json()

def download_image(layer_digest, headers):
    """Download a Docker image layer and save it to a file."""
    layer_url = f"{registry}{image_name}/blobs/{layer_digest}"
    layer_response = requests.get(layer_url, headers=headers, stream=True)
    layer_response.raise_for_status()
    
    images_dir = "images"
    if not os.path.exists(images_dir):
        os.makedirs(images_dir)
    layer_filename = os.path.join(images_dir, f"{image_name}_{image_tag}.tar")
    with open(layer_filename, 'wb') as f:
        for chunk in layer_response.iter_content(chunk_size=8192):
            f.write(chunk)
    # print(f"Layer {layer_digest} downloaded as {layer_filename}.")

def docker_img(image):

    global image_id, image_name, image_tag, repository_prefix, registry

    if '/' in image:
        parts = image.split('/')
        repository_prefix = parts[0]
        image_id = parts[1]
    else:
        repository_prefix = 'library'
        image_id = image

    image_name, image_tag = image_id.split(':')
    registry = f"https://registry-1.docker.io/v2/{repository_prefix}/"

    add_sbom("Image", image_id)

    print(f"Pulling {image_id}...")

    arch = platform.machine().lower()
    #token for authentication
    token = get_auth_token()
    # Headers for requests
    headers = {
        'Authorization': f"Bearer {token}",
        'Accept': 'application/vnd.docker.distribution.manifest.list.v2+json,'
                  'application/vnd.docker.distribution.manifest.v2+json,'
                  'application/vnd.oci.image.index.v1+json,'
                  'application/vnd.oci.image.manifest.v1+json'
    }
    # Fetch manifest index
    manifest_url = f"{registry}{image_name}/manifests/{image_tag}"
    # print("Manifest URL: ", manifest_url)
    manifest_data = fetch_json(manifest_url, headers)
    # print(f"Manifest Data: {json.dumps(manifest_data, indent=2)}")

    valid_architectures = {m['platform']['architecture'] for m in manifest_data['manifests']}
    image_arch = arch if arch in valid_architectures else 'amd64'

    selected_manifest = next((m for m in manifest_data['manifests'] if m['platform']['architecture'] == image_arch), None)

    if not selected_manifest:
        print(f"No manifest found for architecture: {image_arch}.")
        return
    
    manifest_digest = selected_manifest['digest']
    specific_manifest_url = f"{registry}{image_name}/manifests/{manifest_digest}"
    # print(f"Specific Manifest URL: {specific_manifest_url}")

    specific_manifest = fetch_json(specific_manifest_url, headers)
    # print(f"Specific Manifest: {json.dumps(specific_manifest, indent=2)}")

    image_layer = specific_manifest.get('layers', [])
    download_image(image_layer[-1]['digest'], headers)

    config_url = f"{registry}/{image_name}/blobs/{specific_manifest['config']['digest']}"
    config = fetch_json(config_url, headers)
    # print(json.dumps(config, indent=2))

    # scan the image_with_metadata
    image_info = gen_image_info(config)
    
    # Add the image info to the SBOM
    add_sbom('Image_Info', image_info)

    # Extract the image
    Extract(image_id)

    sbom = get_sbom()
    print(json.dumps(sbom, indent=4))
    # print no of packages
    try:
        print(f"Total number of packages Found: {len(sbom['components']['Packages'])}")
        print(f"Total number of Secrets Found: {len(sbom['components']['Secrets'])}")
    except:
        print("No Packages/Secrets found")
        pass

    # # Scan the extracted files
    scan_vuln(sbom)
