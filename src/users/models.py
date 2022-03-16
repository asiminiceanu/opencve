import imp
from multiprocessing.spawn import old_main_modules
from re import I

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import F

from core.models import BaseModel, Product, Vendor


def get_default_filters():
    return {
        "cvss": 0,
        "event_types": [
            "new_cve",
            "first_time",
            "references",
            "cvss",
            "cpes",
            "summary",
            "cwes",
        ],
    }


def get_default_settings():
    return {"activities_view": "all"}


class User(BaseModel, AbstractUser):
    class Meta:
        db_table = "opencve_users"

    class FrequencyNotification(models.TextChoices):
        ONCE = "once", "Once a day"
        ALWAYS = "always", "As soon as a change is detected"

    enable_notifications = models.BooleanField(default=True)
    filters_notifications = models.JSONField(default=get_default_filters)
    settings = models.JSONField(default=get_default_settings)
    frequency_notifications = models.CharField(
        max_length=6,
        choices=FrequencyNotification.choices,
        default=FrequencyNotification.ALWAYS,
    )

    vendors = models.ManyToManyField(Vendor)
    products = models.ManyToManyField(Product)

    def __str__(self):
        return self.username

    def get_raw_vendors(self):
        vendors = list(
            User.objects.filter(id=self.id)
            .select_related("vendors")
            .values(
                vendor_id=F("vendors__id"),
                vendor_name=F("vendors__name"),
            )
        )

        if len(vendors) == 1 and set(vendors[0].values()) == {None}:
            return []

        return vendors

    def get_raw_products(self):
        products = list(
            User.objects.filter(id=self.id)
            .select_related("products")
            .select_related("vendors")
            .values(
                vendor_id=F("products__vendor__id"),
                vendor_name=F("products__vendor__name"),
                product_id=F("products__id"),
                product_name=F("products__name")
            )
        )
        if len(products) == 1 and set(products[0].values()) == {None}:
            return []

        return products
