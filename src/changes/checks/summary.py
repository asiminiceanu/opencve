from changes.checks.base import BaseCheck
from changes.utils import CveUtil


class Summary(BaseCheck):
    def execute(self):
        summary = self.cve_json["cve"]["description"]["description_data"][0]["value"]

        # Check if the summary has changed
        if self.cve_obj.summary != summary:
            # Replace it in the CVE
            old = self.cve_obj.summary
            self.cve_obj.summary = summary
            self.cve_obj.save()

            # Create a 'summary' event
            event = CveUtil.prepare_event(
                self.cve_obj,
                self.cve_json,
                "summary",
                {"old": old, "new": self.cve_obj.summary},
            )
            return event

        return None
