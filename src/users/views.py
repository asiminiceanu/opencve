from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.views import (
    LoginView,
    PasswordResetConfirmView,
    PasswordResetView,
)
from django.urls import reverse_lazy

from users.forms import LoginForm, PasswordResetForm, RegisterForm, SetPasswordForm


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
