import logging
from difflib import HtmlDiff

import arrow
from nested_lookup import nested_lookup

from changes.models import Change, Event
from core.models import Cve, Cwe, Product, Vendor
from core.utils import convert_cpes, flatten_vendors, get_cwes

logger = logging.getLogger(__name__)


class CveUtil(object):
    @classmethod
    def cve_has_changed(cls, cve_db, cve_json):
        return arrow.get(cve_json["lastModifiedDate"]).datetime != cve_db.updated_at

    @classmethod
    def prepare_event(cls, cve_obj, cve_json, type, payload={}):
        event = Event(
            created_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
            updated_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
            cve=cve_obj,
            type=type,
            details=payload,
            is_reviewed=False,
        )
        return event

    @classmethod
    def create_change(cls, cve_obj, cve_json, task, events):
        change = Change(
            created_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
            updated_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
            cve=cve_obj,
            task=task,
            json=cve_json,
        )
        change.save()

        for event in events:
            event.change = change
            event.save()

        return change

    @classmethod
    def create_cve(cls, cve_json):
        cvss2 = (
            cve_json["impact"]["baseMetricV2"]["cvssV2"]["baseScore"]
            if "baseMetricV2" in cve_json["impact"]
            else None
        )
        cvss3 = (
            cve_json["impact"]["baseMetricV3"]["cvssV3"]["baseScore"]
            if "baseMetricV3" in cve_json["impact"]
            else None
        )

        # Construct CWE and CPE lists
        cwes = get_cwes(
            cve_json["cve"]["problemtype"]["problemtype_data"][0]["description"]
        )
        cpes = convert_cpes(cve_json["configurations"])
        vendors = flatten_vendors(cpes)

        # Create the CVE
        cve = Cve.objects.create(
            cve_id=cve_json["cve"]["CVE_data_meta"]["ID"],
            summary=cve_json["cve"]["description"]["description_data"][0]["value"],
            json=cve_json,
            vendors=vendors,
            cwes=cwes,
            cvss2=cvss2,
            cvss3=cvss3,
            created_at=arrow.get(cve_json["publishedDate"]).datetime,
            updated_at=arrow.get(cve_json["lastModifiedDate"]).datetime,
        )

        # Add the CWE that not exists yet in database
        for cwe in cwes:
            cwe_obj = Cwe.objects.filter(cwe_id=cwe).first()
            if not cwe_obj:
                logger.info(
                    f"{cwe} detected in {cve.cve_id} but not existing in database, adding it..."
                )
                cwe_obj = Cwe.objects.create(cwe_id=cwe)

        # Add the CPEs
        vendors_products = convert_cpes(
            nested_lookup("cpe23Uri", cve_json["configurations"])
        )
        for vendor, products in vendors_products.items():
            v_obj = Vendor.objects.filter(name=vendor).first()

            # Create the vendor
            if not v_obj:
                v_obj = Vendor.objects.create(name=vendor)

            # Create the products
            for product in products:
                p_obj = Product.objects.filter(name=product, vendor=v_obj).first()
                if not p_obj:
                    p_obj = Product.objects.create(name=product, vendor=v_obj)

        return cve


class CustomHtmlHTML(HtmlDiff):
    def __init__(self, *args, **kwargs):
        self._table_template = """
        <table class="table table-diff table-condensed">
            <thead>
                <tr>
                    <th colspan="2">Old JSON</th>
                    <th colspan="2">New JSON</th>
                </tr>
            </thead>
            <tbody>%(data_rows)s</tbody>
        </table>"""
        super().__init__(*args, **kwargs)

    def _format_line(self, side, flag, linenum, text):
        text = text.replace("&", "&amp;").replace(">", "&gt;").replace("<", "&lt;")
        text = text.replace(" ", "&nbsp;").rstrip()
        return '<td class="diff_header">%s</td><td class="break">%s</td>' % (
            linenum,
            text,
        )
