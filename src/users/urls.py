from django.contrib.auth import views
from django.urls import include, path

from users.views import (
    CustomPasswordResetConfirmView,
    CustomPasswordResetView,
    subscriptions,
)

urlpatterns = [
    path("password_reset/", CustomPasswordResetView.as_view(), name="password_reset"),
    path(
        "reset/<uidb64>/<token>/",
        CustomPasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("subscriptions", subscriptions, name="subscriptions"),
    path("", include("django.contrib.auth.urls")),
]
