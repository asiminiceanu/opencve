from itertools import product
import json

from django.utils.functional import cached_property
from django.http import Http404
from django.shortcuts import redirect
from django.views.generic import DetailView, ListView
from django.core.paginator import Paginator

from changes.forms import ActivitiesViewForm
from changes.models import Change
from changes.utils import CustomHtmlHTML
from core.constants import PRODUCT_SEPARATOR
from users.models import User

from django.core.paginator import Paginator
from django.utils.functional import cached_property


class ActivityPaginator(Paginator):
    """
    A custom paginator used to improve the performance of the changes
    list. The count number is much larger than expected, so Django doesn't
    have to compute it.
    See: https://pganalyze.com/blog/pagination-django-postgres#pagination-in-django-option-1--removing-the-count-query
    """

    @cached_property
    def count(self):
        return 9999999999


class ChangeListView(ListView):
    model = Change
    context_object_name = "changes"
    template_name = "changes/change_list.html"
    paginate_by = 20
    paginator_class = ActivityPaginator
    form_class = ActivitiesViewForm

    def _get_user_vendors(self):
        return [v.name for v in self.request.user.vendors.all()]

    def _get_user_products(self):
        products = list(
            User.objects.filter(id=self.request.user.id)
            .select_related("products")
            .select_related("vendors")
            .values_list("products__vendor__name", "products__name")
        )
        if len(products) == 1 and products[0] == (None, None):
            return []
        return products

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("cves")
        return super().dispatch(request, *args, **kwargs)

    def get_queryset(self):
        query = Change.objects
        query = query.select_related("cve").prefetch_related("events")

        # Filter on user subscriptions
        if self.request.user.settings["activities_view"] == "subscriptions":
            vendors = self._get_user_vendors()
            vendors.extend(
                [
                    f"{product[0]}{PRODUCT_SEPARATOR}{product[1]}"
                    for product in self._get_user_products()
                ]
            )

            if vendors:
                query = query.filter(cve__vendors__has_any_keys=vendors)

        return query.order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Add the user subscriptions (TODO: refactor with previous same query)
        context["vendors"] = self._get_user_vendors()
        context["products"] = self._get_user_products()

        # Add the view form
        view = self.request.user.settings["activities_view"]
        context["form"] = ActivitiesViewForm(initial={"view": view})
        return context

    def post(self, request, *args, **kwargs):
        form = ActivitiesViewForm(request.POST)
        if form.is_valid():
            self.request.user.settings = {
                **self.request.user.settings,
                "activities_view": form.cleaned_data["view"],
            }
            self.request.user.save()
        return redirect("home")


class ChangeDetailView(DetailView):
    model = Change
    template_name = "changes/change_detail.html"

    def get_object(self):
        change_id = self.kwargs["id"]
        cve_id = self.kwargs["cve_id"]

        change = Change.objects.filter(cve__cve_id=cve_id).filter(id=change_id).first()
        if not change:
            raise Http404(f"Change {change_id} not found for {cve_id}")
        return change

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        change = context["change"]

        previous = (
            Change.objects.filter(created_at__lt=change.created_at)
            .filter(cve=change.cve)
            .order_by("-created_at")
            .first()
        )

        previous_json = {}
        if previous:
            previous_json = previous.json

        differ = CustomHtmlHTML()
        context["diff"] = differ.make_table(
            fromlines=json.dumps(previous_json, sort_keys=True, indent=2).split("\n"),
            tolines=json.dumps(change.json, sort_keys=True, indent=2).split("\n"),
            context=True,
        )
        return context
