from audioop import reverse
import json

from django.http import Http404
from django.shortcuts import redirect
from django.views.generic import DetailView, ListView

from changes.models import Change
from changes.utils import CustomHtmlHTML


class ChangeListView(ListView):
    model = Change
    context_object_name = "changes"
    template_name = "changes/change_list.html"
    #paginate_by = 20
    
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("cves")
        return super().dispatch(request, *args, **kwargs)
    
    def get_queryset(self):
        query = Change.objects
        query = query.select_related("cve").prefetch_related("events")
        # TODO: check user settings (all activities or subscriptions ones)
        return query.order_by("-created_at")[:20]


class ChangeDetailView(DetailView):
    model = Change
    template_name = "changes/change_detail.html"

    def get_object(self):
        change_id = self.kwargs['id']
        cve_id = self.kwargs['cve_id']

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
