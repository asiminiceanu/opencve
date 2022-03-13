from nested_lookup import nested_lookup

from changes.checks.base import BaseCheck
from changes.utils import CveUtil
from core.models import Product, Vendor
from core.utils import convert_cpes, flatten_vendors


class Cpes(BaseCheck):
    def execute(self):
        old = nested_lookup("cpe23Uri", self.cve_obj.json["configurations"])
        new = nested_lookup("cpe23Uri", self.cve_json["configurations"])

        payload = {
            "added": list(set(new) - set(old)),
            "removed": list(set(old) - set(new)),
        }

        # The CPEs list has been modified
        if payload["added"] or payload["removed"]:

            # Change the CVE's vendors attribute
            self.cve_obj.vendors = flatten_vendors(
                convert_cpes(self.cve_json["configurations"])
            )
            self.cve_obj.save()

            # Create the vendors and products objects if they don't exist
            vendors_products = convert_cpes(payload["added"])

            for vendor, products in vendors_products.items():
                v_obj = Vendor.objects.filter(name=vendor).first()

                # Create the vendor and associate it to the CVE
                if not v_obj:
                    v_obj = Vendor.objects.create(name=vendor)

                # Do the same for its products
                for product in products:
                    p_obj = Product.objects.filter(name=product, vendor=v_obj).first()
                    if not p_obj:
                        p_obj = Product.objects.create(name=product, vendor=v_obj)

            # Create the event
            event = CveUtil.prepare_event(self.cve_obj, self.cve_json, "cpes", payload)
            return event

        return None
