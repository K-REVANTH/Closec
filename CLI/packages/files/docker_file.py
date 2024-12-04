from packages.docker.sbom import add_sbom, get_sbom
import re 

df_info = {}

def dockerfile_scan(dockerfile):
    with open(dockerfile, 'r') as file:
        lines = file.readlines()
        for line in lines:
            if "FROM" in line:
                base_image = line.split(" ")[1].strip()
                df_info["Base_Image"] = base_image
            if "LABEL" in line:
                # LABEL maintainer "Jessie Frazelle <jess@linux.com>"
                # I want to get the data after LABEL maintainer
                maintainer = line.split("LABEL maintainer ")[1].strip()
                df_info["Maintainer"] = maintainer

            package_names = set()
            # Regular expression to match apk package installation commands
            pattern = re.compile(r'^\s*RUN\s+apk\s+--no-cache\s+add\s+(.+?)\s', re.MULTILINE)
            
            matches = pattern.findall(line)
            for match in matches:
                # Split package names and add to the set
                package_names.update(match.split())
        
        df_info["Packages"] = list(package_names)

        print(package_names)

    add_sbom('Dockerfile_Info', df_info["Base_Image"])
    add_sbom('Dockerfile-Packages', df_info["Packages"])
    add_sbom('Secrets', df_info["Maintainer"])