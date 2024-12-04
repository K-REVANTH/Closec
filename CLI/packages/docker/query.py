import psycopg2, re
from rich.console import Console
from rich.table import Table


console = Console()

table = Table(show_header=True, header_style="bold magenta")
table.add_column("Library")
table.add_column("Version")
table.add_column("CVE")
table.add_column("Severity")
table.add_column("Score")

def extract_version(version):
    # Define the regex pattern for extracting the first two numbers separated by a dot
    pattern = re.compile(r'^(\d+)\.(\d+)')
    match = pattern.match(version)
    
    if match:
        return f"{match.group(1)}.{match.group(2)}"
    else:
        return version

def run_query(conn, package_name, package_version):
    # print(f'%{package_name}:{package_version}%')
    cursor = conn.cursor()
    package_version = extract_version(package_version)
    # cursor.execute("SELECT * FROM cve WHERE cpe23uri LIKE %s and SUBSTRING(cve_id FROM 5 FOR 4)::INTEGER >= 2016", (f'%{package_name}:{package_version}%',))
    cursor.execute("SELECT * FROM cve WHERE cpe23uri LIKE %s", (f'%{package_name}:{package_version}%',))
    # cursor.execute("SELECT * FROM cve WHERE cpe23uri LIKE %s", (f'%{package_name}:%',))
    results = cursor.fetchall()
    # print(results)
    cursor.close()
    return results

def scan_vuln(sbom):
    packages = sbom["components"]["Packages"]
    conn = psycopg2.connect(
        dbname="closec_cve",
        user="postgres",
        password="Postgres@SQL",
        host="localhost",
        port="5432"
    )

    for package_name, package_version in packages.items():
        results = run_query(conn, package_name, package_version)
        for result in results:
            if results:
                # print(results)
                # print([package_name, package_version, result[0], result[1], result[2]])
                table.add_row(package_name, package_version, result[0], result[2], str(result[1]))

    console.print(table)
    conn.close()
