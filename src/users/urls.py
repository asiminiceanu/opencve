from django.contrib.auth import views
from django.urls import include, path

from users.views import (CustomPasswordResetConfirmView,
                         CustomPasswordResetView, SubscriptionsView, account,
                         subscribe)

urlpatterns = [
    path("", account, name="account"),
    path("subscriptions", SubscriptionsView.as_view(), name="subscriptions"),
    path("password_reset/", CustomPasswordResetView.as_view(), name="password_reset"),
    path(
        "reset/<uidb64>/<token>/",
        CustomPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("subscribe", subscribe, name="subscribe"),
    path("", include("django.contrib.auth.urls")),
]
