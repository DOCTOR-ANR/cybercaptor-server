#!/usr/bin/python

#from apparmor.aa import log

__author__ = 'tai'

from xml.etree.ElementTree import parse, Element, ElementTree, iterparse
import glob
from os import path
import sqlite3
from datetime import date
import logging
import os.path
import urllib2
import glob

NVD_FILE_PATH = "./resources/nvd/"
DATABASE_PATH = '../vulnerability-remediation-database.db'
NVD_FIRST_YEAR = 2002
NVD_CURRENT_YEAR = date.today().year
COMMON_URL_START = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-"
COMMON_URL_END = ".xml.gz"
FILENAME_PREFIX = "nvdcve-2.0-"
FILENAME_POSTFIX = ".xml"
FILENAME_POSTFIX_COMPRESSED = ".xml.gz"
CWE_FILE_PATH = "./resources/cwe/cwec_v2.8.xml"


def download_file_with_progress_bar(url, to_path):
    file_name = url.split('/')[-1]
    u = urllib2.urlopen(url)
    f = open(to_path, 'wb')
    meta = u.info()
    file_size = int(meta["Content-Length"])

    file_size_dl = 0
    block_sz = 65536
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break

        file_size_dl += len(buffer)
        f.write(buffer)
        p = float(file_size_dl) / file_size
        status = r"{0}  [{1:.2%}]".format(file_size_dl, p)
        status += chr(8) * (len(status) + 1)
        logging.debug("downloading " + to_path + " --- " + status)

    f.close()


def extract_namespaces_from_xml(xml_file_path):
    namespaces = {}
    xml = None
    for event, elem in iterparse(xml_file_path, ('start', 'start-ns')):
        if event == 'start-ns':
            if elem[0] in namespaces and namespaces[elem[0]] != elem[1]:
                # NOTE: It is perfectly valid to have the same prefix refer
                # to different URI namespaces in different parts of the
                # document. This exception serves as a reminder that this
                # solution is not robust.    Use at your own peril.
                raise KeyError("Duplicate prefix with different URI found.")

            namespaces[str(elem[0])] = elem[1]

        elif event == 'start':
            if xml is None:
                xml = elem
                break
    return namespaces


def download_nvd():
    # ex of URL : http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-2002.xml
    for year in range(NVD_FIRST_YEAR, NVD_CURRENT_YEAR + 1):
        filename = FILENAME_PREFIX + str(year) + FILENAME_POSTFIX
        filename_compressed = FILENAME_PREFIX + str(year) + FILENAME_POSTFIX_COMPRESSED
        logging.info("Processing NVD file of " + str(year) + " : " + filename)

        path = NVD_FILE_PATH + filename
	path_compressed = NVD_FILE_PATH + filename_compressed

        if os.path.isfile(path) and year < NVD_CURRENT_YEAR:
            logging.info("Old NVD file already exists, skipping it")
        else:
            logging.info("NVD file doesn't exist or the year is current year, I will download it.")
            url = COMMON_URL_START + str(year) + COMMON_URL_END
            logging.info("Downloading " + url + "...")
            download_file_with_progress_bar(url, path_compressed)
	    os.system("gunzip -f " + path_compressed)
	    logging.info("Uncompressing...")

            # print(url)


def create_tables(db_cursor):
    db_cursor.execute(
        "CREATE TABLE IF NOT EXISTS vulnerability (id INTEGER PRIMARY KEY AUTOINCREMENT, cve TEXT UNIQUE, description TEXT, cvss_id INTEGER)")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_vuln_cve ON vulnerability (cve ASC);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_vuln_id ON vulnerability (id ASC);")
    db_cursor.execute(
        "CREATE TABLE IF NOT EXISTS rules (id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT,description TEXT, sid INTEGER, gid INTEGER);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_rules ON rules (id ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS rules_vulnerability (id_rule INTEGER, id_vulnerability INTEGER);")
    db_cursor.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS index_rules_vulnerability ON rules_vulnerability (id_rule ASC, id_vulnerability ASC);")
    db_cursor.execute(
        "CREATE TABLE IF NOT EXISTS patchs (id INTEGER PRIMARY KEY AUTOINCREMENT, link TEXT, description TEXT);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_patchs_id ON patchs (id ASC);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_patchs_link ON patchs (link ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS patchs_vulnerability (id_patch INTEGER, id_vulnerability INTEGER);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_patchs_vulnerability ON patchs_vulnerability (id_patch ASC, id_vulnerability ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS cvss (id INTEGER PRIMARY KEY AUTOINCREMENT, score REAL, access_vector TEXT, access_complexity TEXT , authentication TEXT, confidentiality_impact TEXT, integrity_impact TEXT, availability_impact TEXT);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_cvss ON cvss (id ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS cpe (id INTEGER PRIMARY KEY AUTOINCREMENT, cpe_id TEXT);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_cpe_id ON cpe (id ASC);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_cpe_cpe_id ON cpe (cpe_id ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS cpe_vulnerability (id_cpe INTEGER, id_vulnerability INTEGER);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_cpe_vulnerability ON cpe_vulnerability (id_cpe ASC, id_vulnerability ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS cwe_vulnerability (id_cwe INTEGER, id_vulnerability INTEGER);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_cwe_vulnerability ON cwe_vulnerability (id_cwe ASC, id_vulnerability ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS cwe (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT, abstraction TEXT);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_cwe ON cwe (id ASC);")
    db_cursor.execute("CREATE TABLE IF NOT EXISTS cwe_relations(id_parent INTEGER, id_child INTEGER, target_form TEXT);")
    db_cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS index_cwe_relations ON cwe_relations (id_parent ASC, id_child ASC);")


def update_database(db_cursor):
    for nvd_xml_file in sorted(glob.glob(NVD_FILE_PATH + "*.xml"), key=os.path.basename):
        add_file_to_database(nvd_xml_file, db_cursor)


def add_file_to_database(file_path, db_cursor):
    logging.info("Adding the file " + file_path + " to the vulnerability and remediation database.")
    number_of_added_vulnerability = 0

    tree = parse(file_path)
    root = tree.getroot()
    assert isinstance(root, Element)
    namespaces = {
        'xmlns': 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
        'patch': 'http://scap.nist.gov/schema/patch/0.1',
        'vuln': 'http://scap.nist.gov/schema/vulnerability/0.4',
        'cvss': 'http://scap.nist.gov/schema/cvss-v2/0.2',
        'cpe-lang': 'http://cpe.mitre.org/language/2.0',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        'scap-core': 'http://scap.nist.gov/schema/scap-core/0.1'
    }

    for entry in root.findall("xmlns:entry", namespaces=namespaces):
        try:
            assert isinstance(entry, Element)
            # CVE
            cve = entry.attrib['id']
            description = entry.find('vuln:summary', namespaces=namespaces).text

            # add to db
            db_cursor.execute("SELECT id FROM vulnerability WHERE cve=?", (cve,))
            res = db_cursor.fetchone()
            already_in_db = (res != None)
            if not already_in_db:
                logging.debug("Adding the vulnerability " + cve + " to the database.")
                # We add the vulnerability to the database, else, we pass everything else for this vulnerability.

                # First, we add the CVSS
                cvss = entry.find('vuln:cvss', namespaces=namespaces)
                if cvss:
                    base_metrics = cvss.find('cvss:base_metrics', namespaces=namespaces)
                    if base_metrics:
                        score = base_metrics.find('cvss:score', namespaces=namespaces).text
                        access_vector = base_metrics.find('cvss:access-vector', namespaces=namespaces).text
                        access_complexity = base_metrics.find('cvss:access-complexity', namespaces=namespaces).text
                        authentication = base_metrics.find('cvss:authentication', namespaces=namespaces).text
                        confidentiality_impact = base_metrics.find('cvss:confidentiality-impact',
                                                                   namespaces=namespaces).text
                        integrity_impact = base_metrics.find('cvss:integrity-impact', namespaces=namespaces).text
                        availability_impact = base_metrics.find('cvss:availability-impact', namespaces=namespaces).text

                db_cursor.execute(
                    "INSERT INTO cvss (score, access_vector, access_complexity , authentication, confidentiality_impact, integrity_impact, availability_impact) VALUES (?,?,?,?,?,?,?)",
                    (score, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact,
                     availability_impact))
                id_cvss = db_cursor.lastrowid

                db_cursor.execute("INSERT INTO vulnerability (cve, description, cvss_id) VALUES (?,?,?)",
                                      (cve, description, id_cvss))
                id_vulnerability = db_cursor.lastrowid

                # For the vulnerability, add all the PATCHES
                for vuln_reference in entry.findall('vuln:references', namespaces=namespaces):
                    if vuln_reference.attrib['reference_type'] == "PATCH":
                        patch = vuln_reference.find('vuln:reference', namespaces=namespaces)
                        patch_link = patch.attrib['href']
                        patch_description = patch.text

                        # Search if the patch is already in the database
                        db_cursor.execute("SELECT id FROM patchs WHERE link=?", (patch_link,))
                        res = db_cursor.fetchone()
                        already_in_db = (res is not None )
                        if not already_in_db:
                            # insert the patch
                            db_cursor.execute("INSERT INTO patchs (link, description) VALUES (?,?)",
                                              (patch_link, patch_description))

                            id_patch = db_cursor.lastrowid

                            db_cursor.execute("INSERT INTO patchs_vulnerability (id_patch, id_vulnerability) VALUES (?,?)",
                                              (id_patch, id_vulnerability))
                        else:
                            # the patch is already in the database
                            id_patch = res[0]
                            db_cursor.execute("REPLACE INTO patchs_vulnerability (id_patch, id_vulnerability) VALUES (?,?)",
                                              (id_patch, id_vulnerability))

                # Add the CPE related to this vulnerability
                vuln_soft = entry.find('vuln:vulnerable-software-list', namespaces=namespaces)
                if vuln_soft:
                    for product in vuln_soft.findall('vuln:product', namespaces=namespaces):
                        cpe = product.text

                        # Search if the cpe is already in the database
                        db_cursor.execute("SELECT id FROM cpe WHERE cpe_id=?", (cpe,))
                        res = db_cursor.fetchone()
                        already_in_db = res is not None
                        if not already_in_db:
                            # insert the cpe
                            db_cursor.execute("INSERT INTO cpe (cpe_id) VALUES (?)",
                                              (cpe,))

                            id_cpe = db_cursor.lastrowid

                            db_cursor.execute("INSERT INTO cpe_vulnerability (id_cpe, id_vulnerability) VALUES (?,?)",
                                              (id_cpe, id_vulnerability))
                        else:
                            # the patch is already in the database
                            id_cpe = res[0]
                            db_cursor.execute("INSERT INTO cpe_vulnerability (id_cpe, id_vulnerability) VALUES (?,?)",
                                              (id_cpe, id_vulnerability))

                # Add the CWE related to this vulnerability

                for vuln_cwe in entry.findall('vuln:cwe', namespaces=namespaces):
                    vuln_cwe_id = vuln_cwe.attrib['id']
                    vuln_cwe_id = vuln_cwe_id[4:]

                    if vuln_cwe_id:
                        db_cursor.execute("REPLACE INTO cwe_vulnerability (id_cwe, id_vulnerability) VALUES (?,?)",
                                          (vuln_cwe_id, id_vulnerability))

                number_of_added_vulnerability += 1
            else:
                logging.debug("The vulnerability " + cve + " is already in the database.")
        except Exception as e:
            print("Exception caught: " + str(e) )
    logging.info(str(number_of_added_vulnerability) + " vulnerabilities added to the database")


def add_cwe_file_to_database(db_cursor, file_path):
    logging.info("Adding the CWE file " + file_path + " to the database.")

    tree = parse(file_path)
    root = tree.getroot()
    assert isinstance(root, Element)
    namespaces = {
        'xmlns': 'http://scap.nist.gov/schema/feed/vulnerability/2.0',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance',
        'capec': 'http://capec.mitre.org/capec-2',
    }

    weaknesses = root.find("Weaknesses")
    for entry in weaknesses.findall("Weakness", namespaces=namespaces):
        assert isinstance(entry, Element)
        cwe_id = entry.attrib['ID']
        cwe_name = entry.attrib['Name']
        cwe_description = entry.find("Description").find("Description_Summary").text
        cwe_abstraction = entry.attrib['Weakness_Abstraction']

        db_cursor.execute("REPLACE INTO cwe (id, name, description, abstraction) VALUES (?,?,?,?)", (cwe_id, cwe_name, cwe_description, cwe_abstraction))
        id_cwe = db_cursor.lastrowid

        if entry.find("Relationships"):
            for relationship in entry.find("Relationships").findall("Relationship"):
                relationship_nature = relationship.find("Relationship_Nature").text
                if relationship_nature == "ChildOf":
                    id_parent = relationship.find("Relationship_Target_ID").text
                    target_form = relationship.find("Relationship_Target_Form").text
                    db_cursor.execute("REPLACE INTO cwe_relations (id_parent, id_child, target_form) VALUES (?,?,?)", (id_parent, cwe_id, target_form))
                else:
                    # TODO : manage other types of relation ships
                    ()


def main():
    logging.basicConfig(level=logging.INFO)

    # Load database
    conn = sqlite3.connect(DATABASE_PATH)
    db_cursor = conn.cursor()

    # Create tables
    create_tables(db_cursor)

    add_cwe_file_to_database(db_cursor, CWE_FILE_PATH)

    # Download the NVD and update the database
    download_nvd()
    update_database(db_cursor)

    # add_file_to_database("./resources/nvd/nvdcve-2.0-2014.xml",db_cursor)


    # Close database
    conn.commit()
    db_cursor.close()


if __name__ == '__main__':
    main()
