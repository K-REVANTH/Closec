import argparse, json

from packages.docker.scan import docker_img
from packages.files.docker_file import dockerfile_scan
from packages.files.requirements import scan_req
from packages.docker.sbom import get_sbom
from packages.files.package_lock import scan_package_lock
from packages.files.yarn_lock import scan_yarn_lock
from database import setup_db

VERSION = "0.2.1"

def print_closec_art():
    art = """\033[38;5;214m
            
         ▄████▄    ██▓      ▒█████     ██████   ▓█████   ▄████▄  
        ▒██▀ ▀█   ▓██▒     ▒██▒  ██▒  ▒██      ▒▓█   ▀  ▒██▀ ▀█  
        ▒▓█       ▒██░     ▒██░  ██▒░  ▓█████  ▒████    ▒▓█     
        ▒▓▓▄ ▄██▒ ▒██░     ▒██   ██░   ▒   ██▒  ▓█   ▄   ▓▓▄ ▄██▒
        ▒ ▓███▀ ░ ░██████▒  ░████▓▒░▒  ██████▒  ██████▒  ▓████▀░
        ░ ░▒ ▒  ░ ░ ▒░░  ░░  ▒░▒░▒░ ▒  ░▒ ▒ ░░  ░ ░░ ░▒    ░ ░ ░
        ░  ▒   ░  ░ ▒  ░  ░  ▒ ▒░ ░ ░▒  ░ ░ ░ ░  ░  ░  ▒    ░ ░
        ░          ░ ░   ░    ░ ▒  ░    ░     ░   ░          ░
    \033[0m"""
    print(art)

if __name__ == "__main__":
    setup_db()
    parser = argparse.ArgumentParser(description="Scan Images, files, and more to reveal vulnerabilities, secrets ... ")
    parser.add_argument('-v', '--version', action='version', version=f"Version: {VERSION}", help='Shows CLOSEC Version.')
    parser.add_argument("-i", "--image", action="store", dest="image", help="The name of the Image.")
    parser.add_argument("-fd", "--dockerfile", action="store", dest="dockerfile", help="Dockerfile.")
    parser.add_argument("-fr", "--requirements-txt", action="store", dest="requirements", help="Requirements file.")
    parser.add_argument("-fp", "--package-json", action="store", dest="package_lock", help="Package.json File.")
    parser.add_argument("-fy", "--yarn-lock", action="store", dest="yarn_lock", help="Yarn.lock File.")
    parser.add_argument("-pN", "--project-nodejs", action="store", dest="project_nodejs", nargs='?', const='.',
                        help=(
                                "Scans your Node.js project using `package-lock.json` and `yarn.lock` files. "
                                "Usage: closec -pN [path/to/project] \n"
                                "If no path is specified, it will default to the current directory."
                            ))
    parser.add_argument("-pP", "--project-python", action="store", dest="project_python", nargs='?', const='.',
                        help=(
                                "Scans your Python Projects using `requirements.txt` in the current directory. "
                                "Usage: closec -pP [path/to/project] \n"
                                "If no path is specified, it will default to the current directory."
                            ))

    args = parser.parse_args()  

    print_closec_art()
    
    if args.image:
        image_name = args.image
        docker_img(image_name)
    elif args.dockerfile:
        print("Scanning Dockerfile")
        dockerfile = args.dockerfile
        dockerfile_scan(dockerfile) 
        print(json.dumps(get_sbom(), indent=4))
    elif args.requirements:
        print("Scanning requirements.txt")
        requirements = args.requirements
        scan_req(requirements)
        print(json.dumps(get_sbom(), indent=4))
    elif args.project_python:
        print("Scanning your Python Project")
        path = f"{args.project_python}/requirements.txt"
        scan_req(path)
        print(json.dumps(get_sbom(), indent=4))
    elif args.package_lock:
        print("Scanning your Package-lock.json file")
        package_lock_file = args.package_lock
        scan_package_lock(package_lock_file)
        print(json.dumps(get_sbom(), indent=4))
    elif args.yarn_lock:
        print("Scanning your Yarn.Lock file")
        yarn_lock_file = args.yarn_lock
        scan_yarn_lock(yarn_lock_file)
        print(json.dumps(get_sbom(), indent=4))
    elif args.project_nodejs:
        print("Scanning your Python Project")
        package_lock_file = f"{args.project_nodejs}/package-lock.json"
        scan_package_lock(package_lock_file)
        yarn_lock_file = f"{args.project_nodejs}/yarn.lock"
        scan_yarn_lock(yarn_lock_file)
        print(json.dumps(get_sbom(), indent=4))
    else:
        print("Scan Images, files, and more to reveal vulnerabilities, secrets ... \nUse -h for more details")