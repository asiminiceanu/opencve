import gzip
import json
import re
from io import BytesIO

import arrow
import requests
from celery import shared_task
from celery.utils.log import get_task_logger

from changes.checks.base import BaseCheck
from changes.models import Task
from changes.utils import CveUtil
from core.models import Cve

NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz"
NVD_MODIFIED_META_URL = (
    "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.meta"
)
logger = get_task_logger(__name__)


def checksum_has_changed():
    logger.info(f"Downloading {NVD_MODIFIED_META_URL}...")
    resp = requests.get(NVD_MODIFIED_META_URL)
    buf = BytesIO(resp.content).read().decode("utf-8")

    matches = re.match(r".*sha256:(\w{64}).*", buf, re.DOTALL)
    nvd_sha256 = matches.group(1)
    last_task = Task.objects.order_by("-created_at").first()

    if nvd_sha256 != last_task.nvd_checksum:
        return True, nvd_sha256
    return False, last_task.nvd_checksum


def download_modified_items():
    logger.info("Downloading {}...".format(NVD_MODIFIED_URL))
    resp = requests.get(NVD_MODIFIED_URL).content
    raw = gzip.GzipFile(fileobj=BytesIO(resp)).read()
    items = json.loads(raw.decode("utf-8"))["CVE_Items"]
    return items


def check_for_update(cve_json, task):
    cve_id = cve_json["cve"]["CVE_data_meta"]["ID"]
    cve_obj = Cve.objects.filter(cve_id=cve_id).first()
    events = []

    # A new CVE has been added
    if not cve_obj:
        cve_obj = CveUtil.create_cve(cve_json)
        logger.info(f"[{cve_id}] New CVE")
        events = [CveUtil.prepare_event(cve_obj, cve_json, "new_cve", {})]

    # Existing CVE has changed
    elif CveUtil.cve_has_changed(cve_obj, cve_json):
        events = []
        checks = BaseCheck.__subclasses__()

        # Loop on each kind of check
        for check in checks:
            c = check(cve_obj, cve_json)
            event = c.execute()

            if event:
                events.append(event)

        # Change the last updated date
        cve_obj.updated_at = arrow.get(cve_json["lastModifiedDate"]).datetime
        cve_obj.json = cve_json
        cve_obj.save()

    # Create the change
    if events:
        CveUtil.create_change(cve_obj, cve_json, task, events)
        logger.info(f"[{cve_obj.cve_id}] CVE has changed ({len(events)} events)")


@shared_task(name="HANDLE_EVENTS")
def handle_events():
    logger.info("Checking for new events...")
    has_changed, checksum = checksum_has_changed()
    if not has_changed:
        logger.info("DB is up to date.")
        return

    # Retrieve the list of modified CVEs
    logger.info("Download modified CVEs...")
    items = download_modified_items()

    # Create the task containing the changes
    task = Task.objects.create(nvd_checksum=checksum)

    logger.info("Checking {} CVEs...".format(len(items)))
    for item in items:
        check_for_update(item, task)
