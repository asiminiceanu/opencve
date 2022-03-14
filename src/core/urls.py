from django.urls import path

from core.views import CveDetailView, CveListView, CweListView, HomeView, VendorListView


urlpatterns = [
    #path("", HomeView.as_view(), name="home"),
    path("cve/", CveListView.as_view(), name="cves"),
    path("cve/<cve_id>", CveDetailView.as_view(), name="cve"),
    path("cwe/", CweListView.as_view(), name="cwes"),
    path("vendors/", VendorListView.as_view(), name="vendors"),
]
