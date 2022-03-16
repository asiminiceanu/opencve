import logging

from changes.checks.base import BaseCheck
from changes.utils import CveUtil
from core.models import Cwe

logger = logging.getLogger(__name__)


class Cwes(BaseCheck):
    def execute(self):
        old = self.cve_obj.cwes
        new = [
            c["value"]
            for c in self.cve_json["cve"]["problemtype"]["problemtype_data"][0][
                "description"
            ]
        ]

        payload = {
            "added": list(set(new) - set(old)),
            "removed": list(set(old) - set(new)),
        }

        # It's possible that a CVE links a CWE not yet defined in database.
        # In this case we'll save it in the `cwes` table and a periodic task
        # will populate later its name and description using the MITRE file.
        for cwe_id in payload["added"]:
            cwe = Cwe.objects.filter(cwe_id=cwe_id).first()

            if not cwe:
                logger.info(
                    f"{cwe_id} detected in {self.cve_obj.cve_id} but not existing in database, adding it..."
                )
                Cwe.objects.create(cwe_id=cwe_id)

        # If the list of CWE changed
        if payload["added"] or payload["removed"]:

            # Save the new list
            self.cve_obj.cwes = new
            self.cve_obj.save()

            # Create the event
            event = CveUtil.prepare_event(self.cve_obj, self.cve_json, "cwes", payload)
            return event

        return None
