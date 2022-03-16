import gzip
import json
import uuid
import xml.etree.ElementTree
from io import BytesIO
from zipfile import ZipFile

import arrow
import requests
import untangle
from cpe import CPE

from changes.management.commands import BaseCommand
from changes.models import Change, Event, Task
from core.models import Cve, Cwe, Product, Vendor
from core.utils import convert_cpes, flatten_vendors, get_cwes


class Command(BaseCommand):
    CURRENT_YEAR = arrow.now().year
    CVE_FIRST_YEAR = 2002
    MITRE_CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    NVD_CVE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
    NVD_CPE_URL = "https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz"

    help = "Import initial data"
    mappings = {
        "cves": [],
        "cwes": [],
        "events": [],
        "changes": [],
        "vendors": {},
        "products": {},
    }

    @staticmethod
    def get_slug(vendor, product=None):
        slug = vendor
        if product:
            slug += "-{}".format(product)
        return slug

    def import_cwe(self):
        with self.timed_operation(f"Downloading {Command.MITRE_CWE_URL}"):
            resp = requests.get(Command.MITRE_CWE_URL).content

        # Parse weaknesses
        with self.timed_operation("Parsing cwes"):
            z = ZipFile(BytesIO(resp))
            raw = z.open(z.namelist()[0]).read()
            obj = untangle.parse(raw.decode("utf-8"))
            weaknesses = obj.Weakness_Catalog.Weaknesses.Weakness
            categories = obj.Weakness_Catalog.Categories.Category

        # Create the objects
        with self.timed_operation("Creating mappings"):
            for c in weaknesses + categories:
                self.mappings["cwes"].append(
                    Cwe(
                        **dict(
                            id=str(uuid.uuid4()),
                            cwe_id=f"CWE-{c['ID']}",
                            name=c["Name"],
                            description=c.Description.cdata
                            if hasattr(c, "Description")
                            else c.Summary.cdata,
                        )
                    )
                )

        with self.timed_operation("Inserting CWE"):
            Cwe.objects.bulk_create(self.mappings["cwes"])

        self.info(
            f"  {self.style.MIGRATE_LABEL(len(self.mappings['cwes']))} CWE imported"
        )
        del self.mappings["cwes"]

    def import_cve(self, task_id, year):
        url = Command.NVD_CVE_URL.format(year=year)
        with self.timed_operation(f"Downloading {url}..."):
            resp = requests.get(url).content

        # Parse the XML elements
        with self.timed_operation("Parsing JSON elements..."):
            raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
            del resp
            items = json.loads(raw.decode("utf-8"))["CVE_Items"]
            del raw

        with self.timed_operation("Creating model objects..."):

            for item in items:
                cve_db_id = str(uuid.uuid4())
                change_db_id = str(uuid.uuid4())

                summary = item["cve"]["description"]["description_data"][0]["value"]
                cvss2 = (
                    item["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
                    if "baseMetricV2" in item["impact"]
                    else None
                )
                cvss3 = (
                    item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
                    if "baseMetricV3" in item["impact"]
                    else None
                )

                # Construct CWE and CPE lists
                cwes = get_cwes(
                    item["cve"]["problemtype"]["problemtype_data"][0]["description"]
                )
                cpes = convert_cpes(item["configurations"])
                vendors = flatten_vendors(cpes)

                # Create the CVE and Change mappings
                created_at = arrow.get(item["publishedDate"]).datetime
                updated_at = arrow.get(item["lastModifiedDate"]).datetime

                self.mappings["cves"].append(
                    Cve(
                        **dict(
                            id=cve_db_id,
                            cve_id=item["cve"]["CVE_data_meta"]["ID"],
                            summary=summary,
                            json=item,
                            vendors=vendors,
                            cwes=cwes,
                            cvss2=cvss2,
                            cvss3=cvss3,
                            created_at=created_at,
                            updated_at=updated_at,
                        )
                    )
                )
                self.mappings["changes"].append(
                    Change(
                        **dict(
                            id=change_db_id,
                            created_at=created_at,
                            updated_at=updated_at,
                            json=item,
                            cve_id=cve_db_id,
                            task_id=task_id,
                        )
                    )
                )
                self.mappings["events"].append(
                    Event(
                        **dict(
                            id=str(uuid.uuid4()),
                            created_at=created_at,
                            updated_at=updated_at,
                            type=Event.EventType.NEW_CVE,
                            details={},
                            is_reviewed=True,
                            cve_id=cve_db_id,
                            change_id=change_db_id,
                        )
                    )
                )

                # Create the vendors and their products
                for vendor, products in cpes.items():

                    # Create the vendor
                    if vendor not in self.mappings["vendors"].keys():
                        self.mappings["vendors"][vendor] = Vendor(
                            **dict(id=str(uuid.uuid4()), name=vendor)
                        )

                    for product in products:
                        if (
                            self.get_slug(vendor, product)
                            not in self.mappings["products"].keys()
                        ):
                            self.mappings["products"][
                                self.get_slug(vendor, product)
                            ] = Product(
                                **dict(
                                    id=str(uuid.uuid4()),
                                    name=product,
                                    vendor_id=self.mappings["vendors"][vendor].id,
                                )
                            )

        # Insert the objects in database
        with self.timed_operation("Inserting CVE..."):
            Cve.objects.bulk_create(self.mappings["cves"])
            Change.objects.bulk_create(self.mappings["changes"])
            Event.objects.bulk_create(self.mappings["events"])

        self.info(
            f"  {self.style.MIGRATE_LABEL(len(self.mappings['cves']))} CVE imported"
        )

        # Free the memory after each processed year
        self.mappings["cves"] = []
        self.mappings["changes"] = []
        self.mappings["events"] = []

    def import_cpe(self):
        with self.timed_operation(f"Downloading {Command.NVD_CPE_URL}..."):
            resp = requests.get(Command.NVD_CPE_URL).content

        # Parse the XML elements
        with self.timed_operation("Parsing XML elements..."):
            raw = gzip.GzipFile(fileobj=BytesIO(resp))
            del resp
            items = set()
            for _, elem in xml.etree.ElementTree.iterparse(raw):
                if elem.tag.endswith("cpe23-item"):
                    items.add(elem.get("name"))
                elem.clear()
            del raw

        # Create the objects
        with self.timed_operation("Creating list of mappings..."):
            for item in items:
                obj = CPE(item)
                vendor = obj.get_vendor()[0]
                product = obj.get_product()[0]

                if vendor not in self.mappings["vendors"].keys():
                    self.mappings["vendors"][vendor] = Vendor(
                        **dict(id=str(uuid.uuid4()), name=vendor)
                    )

                if (
                    self.get_slug(vendor, product)
                    not in self.mappings["products"].keys()
                ):
                    self.mappings["products"][self.get_slug(vendor, product)] = Product(
                        **dict(
                            id=str(uuid.uuid4()),
                            name=product,
                            vendor_id=self.mappings["vendors"][vendor].id,
                        )
                    )
            del items

        # Insert the objects in database
        with self.timed_operation("Inserting Vendors and Products..."):
            Vendor.objects.bulk_create(self.mappings["vendors"].values())
            Product.objects.bulk_create(self.mappings["products"].values())

        self.info(
            f"  {self.style.MIGRATE_LABEL(len(self.mappings['vendors']))} Vendors imported"
        )
        self.info(
            f"  {self.style.MIGRATE_LABEL(len(self.mappings['products']))} Products imported"
        )
        del self.mappings["vendors"]
        del self.mappings["products"]

    def handle(self, *args, **kwargs):
        self.info(self.style.MIGRATE_HEADING("Importing CWE:"))
        self.import_cwe()

        task = Task.objects.create()
        for year in range(Command.CVE_FIRST_YEAR, Command.CURRENT_YEAR + 1):
            self.info(self.style.MIGRATE_HEADING(f"Importing CVE for {year}:"))
            self.import_cve(task.id, year)

        self.info(self.style.MIGRATE_HEADING("Importing CPE:"))
        self.import_cpe()
