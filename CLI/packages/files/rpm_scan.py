# from packages.docker.sbom import add_sbom

# packages = {}

# def scan_rpm(root_dir):

#     add_sbom('Packages', packages)
import sqlite3

# Path to the RPM SQLite database
db_path = 'images/files_oraclelinux_9/var/lib/rpm/rpmdb.sqlite'

def extract_blobs_from_db(db_path):
    # Connect to the SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Execute a query to get all hnum and blob data
    cursor.execute('SELECT hnum, blob FROM Packages')

    # Iterate through the results and save each blob to a file
    for hnum, blob in cursor.fetchall():
        blob_filename = f'blobs/blob_{hnum}.bin'
        with open(blob_filename, 'wb') as f:
            f.write(blob)
        print(f'Saved blob data for hnum {hnum} to {blob_filename}')

    # Close the database connection
    conn.close()

if __name__ == '__main__':
    extract_blobs_from_db(db_path)



#tmp code
# import rpmfile

# with rpmfile.open('E:\Internships\Cy5.io\Github\closec\CLI\images\\files_centos_latest\\var\lib\\rpm\Packages') as rpm:

#     # Inspect the RPM headers
#     print(rpm.headers.keys())
#     print(rpm.headers.get('arch', 'noarch'))

#     # Extract a fileobject from the archive
#     fd = rpm.extractfile('./usr/bin/script')
#     print(fd.read())

#     for member in rpm.getmembers():
#         print(member)