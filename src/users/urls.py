from django.contrib.auth import views
from django.urls import include, path

from users.views import (
    CustomPasswordResetConfirmView,
    CustomPasswordResetView,
    SubscriptionsView,
    TagsView,
    TagDeleteView,
    account,
    subscribe,
)

urlpatterns = [
    path("", account, name="account"),
    path("subscriptions/", SubscriptionsView.as_view(), name="subscriptions"),
    path("tags/", TagsView.as_view(), name="tags"),
    path("tags/<name>/", TagsView.as_view(), name="edit_tag"),
    path("tags/<name>/delete", TagDeleteView.as_view(), name="delete_tag"),
    path("password_reset/", CustomPasswordResetView.as_view(), name="password_reset"),
    path(
        "reset/<uidb64>/<token>/",
        CustomPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("subscribe", subscribe, name="subscribe"),
    path("", include("django.contrib.auth.urls")),
]
