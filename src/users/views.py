from django.contrib import messages
from django.contrib.auth.views import (
    LoginView,
    PasswordResetConfirmView,
    PasswordResetView,
)
from django.views.generic import TemplateView
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404, render, redirect
from django.urls import reverse_lazy

from core.models import Product, Vendor
from users.forms import LoginForm, PasswordResetForm, RegisterForm, SetPasswordForm
from users.utils import is_valid_uuid


def account(request):
    return redirect("subscriptions")


class SubscriptionsView(TemplateView):
    template_name = "users/profile/subscriptions.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["vendors"] = self.request.user.get_raw_vendors()
        context["products"] = self.request.user.get_raw_products()
        return context


class CustomLoginView(LoginView):
    form_class = LoginForm
    template_name = "users/login.html"
    redirect_authenticated_user = True


class CustomPasswordResetView(PasswordResetView):
    form_class = PasswordResetForm
    template_name = "users/password_reset.html"
    success_url = reverse_lazy("login")

    def form_valid(self, form):
        resp = super().form_valid(form)
        messages.success(
            self.request,
            f"We've emailed you instructions for setting your password, if an account exists with the email you entered.",
        )
        return resp


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    form_class = SetPasswordForm
    template_name = "users/password_reset_confirm.html"
    success_url = reverse_lazy("login")

    def form_valid(self, form):
        resp = super().form_valid(form)
        messages.success(
            self.request,
            f"Your password has been set. You may go ahead and log in now.",
        )
        return resp


def register(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            messages.success(
                request, f"Registration successful, email sent to {user.email}"
            )
            return redirect("login")
    else:
        form = RegisterForm()
    return render(
        request=request, template_name="users/register.html", context={"form": form}
    )


def subscribe(request):
    response = {}

    # Only authenticated users can subscribe
    if not request.method == "POST" or not request.user.is_authenticated:
        raise Http404()

    # Handle the parameters
    action = request.POST.get("action")
    obj = request.POST.get("obj")
    obj_id = request.POST.get("id")

    if (
        not all([action, obj, obj_id])
        or not is_valid_uuid(obj_id)
        or action not in ["subscribe", "unsubscribe"]
        or obj not in ["vendor", "product"]
    ):
        raise Http404()

    # Vendor subscription
    if obj == "vendor":
        print(obj_id)
        vendor = get_object_or_404(Vendor, id=obj_id)
        if action == "subscribe":
            request.user.vendors.add(vendor)
            response = {"status": "ok", "message": "vendor added"}
        else:
            request.user.vendors.remove(vendor)
            response = {"status": "ok", "message": "vendor removed"}

    # Product subscription
    if obj == "product":
        product = get_object_or_404(Product, id=obj_id)
        if action == "subscribe":
            request.user.products.add(product)
            response = {"status": "ok", "message": "product added"}
        else:
            request.user.products.remove(product)
            response = {"status": "ok", "message": "product removed"}

    return JsonResponse(response)
