from crispy_forms.helper import FormHelper
from crispy_forms.layout import Submit
from django.contrib import messages
from django.contrib.auth.views import (
    LoginView,
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetView,
)
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse, reverse_lazy
from django.views.generic import ListView, TemplateView, DeleteView, UpdateView

from core.models import Product, Vendor
from users.forms import (
    LoginForm,
    PasswordChangeForm,
    PasswordResetForm,
    ProfileChangeForm,
    RegisterForm,
    SetPasswordForm,
    UserTagForm,
)
from users.models import CveTag, UserTag, User
from users.utils import is_valid_uuid


def account(request):
    return redirect("subscriptions")


class SubscriptionsView(LoginRequiredMixin, TemplateView):
    template_name = "users/account/subscriptions.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["vendors"] = self.request.user.get_raw_vendors()
        context["products"] = self.request.user.get_raw_products()
        return context


class SettingsProfileView(LoginRequiredMixin, UpdateView):
    model = User
    fields = ["first_name", "last_name", "email"]
    template_name = "users/account/settings_profile.html"
    success_url = reverse_lazy("settings_profile")

    def get_object(self, queryset=None):
        return self.request.user

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        form.helper = FormHelper()
        form.helper.add_input(Submit("submit", "Update", css_class="btn-primary"))
        return form

    def form_valid(self, form):
        resp = super().form_valid(form)
        messages.success(
            self.request,
            f"Your profile has been updated.",
        )
        return resp


class SettingsPasswordView(PasswordChangeView):
    form_class = PasswordChangeForm
    template_name = "users/account/settings_password.html"
    success_url = reverse_lazy("settings_password")

    def form_valid(self, form):
        resp = super().form_valid(form)
        messages.success(
            self.request,
            f"Your password has been updated.",
        )
        return resp


class TagsView(LoginRequiredMixin, ListView):
    context_object_name = "tags"
    template_name = "users/account/tags.html"

    def get_queryset(self):
        query = UserTag.objects.filter(user=self.request.user).all()
        return query.order_by("-name")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Create or edit mode
        if self.request.resolver_match.url_name == "tags":
            mode = "create"
            form = UserTagForm()
        else:
            tag = get_object_or_404(
                UserTag, user=self.request.user, name=self.kwargs["name"]
            )
            mode = "update"
            form = UserTagForm(instance=tag)
            form.fields["name"].disabled = True

        context["form"] = form
        context["mode"] = mode
        return context

    def post(self, request, *args, **kwargs):
        if request.resolver_match.url_name == "tags":
            form = UserTagForm(request.user, request.POST)
        else:
            tag = get_object_or_404(UserTag, user=request.user, name=kwargs["name"])
            form = UserTagForm(request.user, request.POST, instance=tag)
            form.fields["name"].disabled = True

        if form.is_valid():

            # In case of new tag, check if the name is unique
            if request.resolver_match.url_name == "tags":
                if UserTag.objects.filter(
                    user=request.user, name=form.cleaned_data["name"]
                ).exists():
                    messages.error(request, "This tag already exists.")
                    return render(
                        request,
                        self.template_name,
                        {"form": form, "tags": self.get_queryset()},
                    )

            # Save or update the tag
            tag = form.save(commit=False)
            tag.user = self.request.user
            tag.save()
            messages.success(
                self.request, f"The tag {tag.name} has been successfully saved."
            )
            return redirect("edit_tag", name=tag.name)

        return render(
            request, self.template_name, {"form": form, "tags": self.get_queryset()}
        )


class TagDeleteView(LoginRequiredMixin, DeleteView):
    model = UserTag
    slug_field = "name"
    slug_url_kwarg = "name"
    template_name = "users/account/delete_tag.html"

    def get_success_url(self):
        obj = self.get_object()
        messages.success(self.request, f"The tag {obj.name} has been deleted.")
        return reverse("tags")

    def get(self, request, *args, **kwargs):
        count = CveTag.objects.filter(
            user=self.request.user, tags__contains=kwargs["name"]
        ).count()
        if count:
            messages.error(
                self.request,
                f"The tag {kwargs['name']} is still associated to {count} CVE(s), detach them before removing the tag.",
            )
            return redirect("tags")
        return super().get(request, *args, **kwargs)


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
