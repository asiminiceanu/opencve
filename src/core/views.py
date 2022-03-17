from hashlib import new
import itertools
import json
import operator

from django.core.paginator import Paginator
from django.db.models import F, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.views.generic import DetailView, ListView

from changes.models import Event
from core.constants import PRODUCT_SEPARATOR
from core.models import Cve, Cwe, Product, Vendor
from core.utils import convert_cpes, get_cwes_details
from users.models import CveTag, UserTag


class CweListView(ListView):
    context_object_name = "cwes"
    template_name = "core/cwe_list.html"
    paginate_by = 20

    def get_queryset(self):
        query = Cwe.objects
        if self.request.GET.get("search"):
            query = query.filter(name__icontains=self.request.GET.get("search"))
        return query.order_by("-name")


class VendorListView(ListView):
    context_object_name = "vendors"
    template_name = "core/vendor_list.html"
    paginate_by = 20

    def get_queryset(self):
        vendors = Vendor.objects.order_by("name").prefetch_related("products")
        if self.request.GET.get("search"):
            vendors = vendors.filter(name__contains=self.request.GET.get("search"))
        return vendors

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get all products or filter them by vendor
        vendor = self.request.GET.get("vendor")
        products = Product.objects.order_by("name").select_related("vendor")

        # Filter by vendor
        if vendor:
            products = products.filter(vendor__name=vendor)

        # Filter by keyword
        if self.request.GET.get("search"):
            products = products.filter(name__contains=self.request.GET.get("search"))

        # List the user subscriptions
        if self.request.user.is_authenticated:
            context["user_vendors"] = self.request.user.vendors.all()
            context["user_products"] = self.request.user.products.all()

        # Add the pagination
        paginator = Paginator(products, 20)
        page_number = self.request.GET.get("product_page")
        context["products"] = paginator.get_page(page_number)
        context["paginator_products"] = paginator

        return context


class CveListView(ListView):
    context_object_name = "cves"
    template_name = "core/cve_list.html"
    paginate_by = 20

    def get_queryset(self):
        query = Cve.objects.order_by("-updated_at")

        # Filter by keyword
        search = self.request.GET.get("search")
        if search:
            query = query.filter(
                Q(cve_id__icontains=search)
                | Q(summary__icontains=search)
                | Q(vendors__contains=search)
            )

        # Filter by CWE
        cwe = self.request.GET.get("cwe")
        if cwe:
            query = query.filter(cwes__contains=cwe)

        # Filter by CVSS score
        cvss = self.request.GET.get("cvss", "").lower()
        if cvss in [
            "empty",
            "low",
            "medium",
            "high",
            "critical",
        ]:
            if cvss == "empty":
                query = query.filter(cvss3__isnull=True)
            if cvss == "low":
                query = query.filter(Q(cvss3__gte=0) & Q(cvss3__lte=3.9))
            if cvss == "medium":
                query = query.filter(Q(cvss3__gte=4.0) & Q(cvss3__lte=6.9))
            if cvss == "high":
                query = query.filter(Q(cvss3__gte=7.0) & Q(cvss3__lte=8.9))
            if cvss == "critical":
                query = query.filter(Q(cvss3__gte=9.0) & Q(cvss3__lte=10.0))

        # Filter by Vendor and Product
        vendor_param = self.request.GET.get("vendor", "").replace(" ", "").lower()
        product_param = self.request.GET.get("product", "").replace(" ", "_").lower()

        if vendor_param:
            vendor = get_object_or_404(Vendor, name=vendor_param)
            query = query.filter(vendors__contains=vendor.name)

            if product_param:
                product = get_object_or_404(Product, name=product_param, vendor=vendor)
                query = query.filter(
                    vendors__contains=f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"
                )

        # Filter by tag
        tag = self.request.GET.get("tag", "").lower()
        if tag and self.request.user.is_authenticated:
            tag = get_object_or_404(UserTag, name=tag, user=self.request.user)
            query = query.filter(cve_tags__tags__contains=tag.name)

        return query

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        vendor = self.request.GET.get("vendor")
        product = self.request.GET.get("product")
        if vendor:
            context["vendor"] = Vendor.objects.get(name=vendor)

            if product:
                context["product"] = Product.objects.get(
                    name=product, vendor=context["vendor"]
                )

        # List the user tags
        if self.request.user.is_authenticated:
            context["user_tags"] = [
                t.name for t in UserTag.objects.filter(user=self.request.user).all()
            ]

        return context


class CveDetailView(DetailView):
    model = Cve
    slug_field = "cve_id"
    slug_url_kwarg = "cve_id"
    template_name = "core/cve_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["cve_dumped"] = json.dumps(context["cve"].json)

        # Add the events history
        events = Event.objects.filter(cve_id=context["cve"].id).order_by("-created_at")
        context["events_by_time"] = [
            (time, list(evs))
            for time, evs in (
                itertools.groupby(events, operator.attrgetter("created_at"))
            )
        ]

        # Add the associated Vendors and CWEs
        context["vendors"] = convert_cpes(context["cve"].json["configurations"])
        context["cwes"] = get_cwes_details(
            context["cve"].json["cve"]["problemtype"]["problemtype_data"][0][
                "description"
            ]
        )

        # Get the CVE tags for the authenticated user
        user_tags = {}
        tags = []

        user = self.request.user
        if user.is_authenticated:
            user_tags = {
                t.name: {"name": t.name, "color": t.color, "description": t.description}
                for t in UserTag.objects.filter(user=self.request.user).all()
            }
            cve_tags = CveTag.objects.filter(
                user=self.request.user, cve=context["cve"]
            ).first()
            if cve_tags:
                tags = [user_tags[cve_tag] for cve_tag in cve_tags.tags]

                # We have to pass an encoded list of tags for the modal box
                context["cve_tags_encoded"] = json.dumps(cve_tags.tags)

        context["user_tags"] = user_tags.keys()
        context["tags"] = tags
        return context

    def post(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            raise Http404()

        cve = self.get_object()
        new_tags = request.POST.getlist("tags", [])

        # Check if all tags are declared by the user
        user_tags = [t.name for t in UserTag.objects.filter(user=request.user).all()]
        for new_tag in new_tags:
            if new_tag not in user_tags:
                raise Http404()

        # Update the CVE tags
        cve_tag = CveTag.objects.filter(user=request.user, cve_id=cve.id).first()
        if not cve_tag:
            cve_tag = CveTag(user=request.user, cve_id=cve.id)
        cve_tag.tags = new_tags
        cve_tag.save()

        return redirect("cve", cve_id=cve.cve_id)
