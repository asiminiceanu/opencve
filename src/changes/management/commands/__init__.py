import time
from contextlib import contextmanager

from django.core.management.base import BaseCommand as DjangoBaseCommand


class BaseCommand(DjangoBaseCommand):
    def error(self, message, ending=None):
        self.stdout.write(f"[error] {message}", ending=ending)

    def info(self, message, ending=None):
        self.stdout.write(f"{message}", ending=ending)

    @contextmanager
    def timed_operation(self, msg):
        start = time.time()
        yield
        self.info(
            "  {}... {} ({}s).".format(
                msg, self.style.SUCCESS("OK"), round(time.time() - start, 3)
            )
        )
