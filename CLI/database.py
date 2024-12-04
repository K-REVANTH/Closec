import requests, os, zipfile, glob, json, csv
from datetime import datetime
import psycopg2
from psycopg2 import connect, sql
from urllib.parse import urljoin
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

nvd_folder = "nvd/"

db_params = {
    'dbname': 'closec_cve',
    'user': 'postgres',
    'password': 'Postgres@SQL',
    'host': 'localhost',
    'port': '5432'
}

def db_exists():
    default_db_params = {
    'dbname': 'postgres',  # Use a default database to check and create other databases
    'user': 'postgres',
    'password': 'Postgres@SQL',
    'host': 'localhost',
    'port': '5432'
    }
    target_db = 'closec_cve'
    
    try:
        # Connect to the default database
        conn = psycopg2.connect(**default_db_params)
        conn.autocommit = True
        cur = conn.cursor()

        cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (target_db,))
        exists = cur.fetchone() is not None

        if not exists:
            cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(target_db)))
            logging.info(f"Database '{target_db}' created successfully.")
        else:
            logging.info(f"Database '{target_db}' already exists.")
            cur.close()
            conn.close()
        return exists

    except Exception as error:
        logging.error(f"Error: {error}")


def create_db():
    conn = psycopg2.connect(**db_params)
    cur = conn.cursor()
    try:
        cur.execute('''
            CREATE TABLE IF NOT EXISTS cve (
                cve_id VARCHAR(255) PRIMARY KEY,
                score REAL,
                severity VARCHAR(50),
                cpe23uri TEXT
            );
            ''')
        
        cur.execute('''
            CREATE TABLE IF NOT EXISTS table_metadata (
                table_name TEXT PRIMARY KEY,
                last_update TIMESTAMP
            );
            ''')

        # Define the trigger function
        cur.execute('''
        CREATE OR REPLACE FUNCTION update_table_metadata()
        RETURNS TRIGGER AS $$
        BEGIN
            INSERT INTO table_metadata (table_name, last_update)
            VALUES ('cve', CURRENT_TIMESTAMP)
            ON CONFLICT (table_name) 
            DO UPDATE SET last_update = EXCLUDED.last_update;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        ''')

        # Create the trigger for insert
        cur.execute('''
        CREATE TRIGGER update_cves_last_insert
        AFTER INSERT ON cve
        FOR EACH ROW
        EXECUTE FUNCTION update_table_metadata();
        ''')

        # Create the trigger for update
        cur.execute('''
        CREATE TRIGGER update_cves_last_update
        AFTER UPDATE ON cve
        FOR EACH ROW
        EXECUTE FUNCTION update_table_metadata();
        ''')

        conn.commit()
        cur.close()
        conn.close()
        update_db()
    
    except Exception as error:
        logging.error(f"Error: {error}")


def update_db():

    try:
        conn = psycopg2.connect(**db_params)
        cur = conn.cursor()
        cur.execute('''
        SELECT last_update FROM table_metadata WHERE table_name = %s;
        ''', ('cve',))

        result = cur.fetchone()

        if result:
            last_update = result[0]
            current_time = datetime.now()
            hours_diff = (current_time - last_update).total_seconds() / 3600

            if hours_diff > 6:
                logging.info("Updating CVE Database!")
                cur.execute('DELETE FROM cve')
                conn.commit()
                cve_psql()
            else:
                logging.info("Database up-to-date!")
        else:
            logging.info("No update timestamp found. Initializing update.")
            cve_psql()


    except Exception as error:
        logging.error(f"Error: {error}")

def download_cve():
    logging.info("Fetching latest CVE data from NVD...")
    nvd_url = "https://nvd.nist.gov/feeds/json/cve/1.1/"
    start_year = 2002
    current_year = datetime.now().year

    if not os.path.exists(nvd_folder):
        os.makedirs(nvd_folder)

    for year in range(start_year, current_year+1):
        file_name = f"nvdcve-1.1-{year}.json.zip"
        file_url = urljoin(nvd_url, file_name)
        local_file_path = os.path.join(nvd_folder, file_name)
        try:
            response = requests.get(file_url, stream=True)
            response.raise_for_status()
            with open(local_file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            with zipfile.ZipFile(local_file_path, 'r') as zip_ref:
                zip_ref.extractall(nvd_folder)
            os.remove(local_file_path)
            # logging.info(f"Downloaded nvdcve-1.1-{year} data successfully!")
        except requests.HTTPError as e:
            logging.info(f"Failed to download {file_url}: {e}")
    logging.info("Fetched data Successfully...")

def cve_psql():
    
    download_cve()
    no_of_cves = 0

    conn = psycopg2.connect(**db_params)
    cur = conn.cursor()

    logging.info("Adding the latest CVEs to your Database...")

    try:
        cve_data = []
        for json_file in glob.glob(f'{nvd_folder}/*.json'):
            with open(json_file, 'r', encoding='utf-8') as file:
                data = json.load(file)
                cve_items = data.get("CVE_Items", [])

                for item in cve_items:
                    cve_id = item['cve']['CVE_data_meta']['ID']

                    cpe23uris = {}
                    for node in item['configurations']['nodes']:
                        for cpe in node['cpe_match']:
                            cpe23uri = cpe['cpe23Uri']
                            vulnerable = cpe['vulnerable']
                            cpe23uris[cpe23uri] = vulnerable
                    cpe23uri = json.dumps(cpe23uris)

                    impact = item.get('impact', {})
                    score = None
                    severity = None

                    if 'baseMetricV3' in impact:
                        score = impact['baseMetricV3']['cvssV3']['baseScore']
                        severity = impact['baseMetricV3']['cvssV3']['baseSeverity']
                    elif 'baseMetricV2' in impact:
                        score = impact['baseMetricV2']['cvssV2']['baseScore']
                        severity = impact['baseMetricV2']['severity']

                    # print(cve_id, score, severity, cpe23uri)
                    cve_data.append((cve_id, score, severity, cpe23uri))
                    no_of_cves += 1

        cur.executemany('''
            INSERT INTO cve (cve_id, score, severity, cpe23uri)
            VALUES (%s, %s, %s, %s)
            ''', cve_data)
        conn.commit()
        logging.info("Successfully added CVE Database with %d CVEs!", no_of_cves)
        
    except Exception as e:
        logging.info("Couldn't update your database!", e)

    finally:
        cur.close()
        conn.close()

def setup_db():
    if db_exists():
        update_db()
        pass
    else:
        logging.info("Creating Database...")
        create_db()