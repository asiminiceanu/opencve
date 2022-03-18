from crispy_forms.helper import FormHelper
from crispy_forms.layout import Layout, Submit, Button, Div, Field, HTML
from crispy_forms.bootstrap import FormActions
from django import forms
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
    UserCreationForm,
)

from users.models import User, UserTag


class LoginForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        self.fields["username"].widget.attrs.update(
            {"placeholder": "Username or email"}
        )
        self.fields["password"].widget.attrs.update({"placeholder": "Password"})
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "username",
            "password",
            Submit("submit", "Sign In", css_class="pull-right btn-flat"),
        )


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("username", "email", "password1", "password2")

    def __init__(self, *args, **kwargs):
        super(RegisterForm, self).__init__(*args, **kwargs)
        self.fields["username"].widget.attrs.update({"placeholder": "Username"})
        self.fields["email"].widget.attrs.update({"placeholder": "Email"})
        self.fields["password1"].widget.attrs.update({"placeholder": "Password"})
        self.fields["password2"].widget.attrs.update(
            {"placeholder": "Confirm Password"}
        )
        self.fields["username"].help_text = None
        self.fields["email"].help_text = None
        self.fields["password1"].help_text = None
        self.fields["password2"].help_text = None
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "username",
            "email",
            "password1",
            "password2",
            Submit("submit", "Register", css_class="btn-block btn-flat"),
        )

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("This username is already in use.")
        return username

    def clean_email(self):
        email = self.cleaned_data["email"]
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already in use.")
        return email

    def save(self, commit=True):
        user = super(RegisterForm, self).save(commit=False)
        user.email = self.cleaned_data["email"]
        if commit:
            user.save()
        return user


class ProfileChangeForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]

    def __init__(self, *args, **kwargs):
        super(ProfileChangeForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            "first_name",
            "last_name",
            "email",
            Submit("submit", "Change Password", css_class="btn btn-primary"),
        )


class PasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super(PasswordChangeForm, self).__init__(*args, **kwargs)
        self.helper = FormHelper()
        self.helper.layout = Layout(
            "old_password",
            "new_password1",
            "new_password2",
            Submit("submit", "Change Password", css_class="btn btn-primary"),
        )


class PasswordResetForm(PasswordResetForm):
    def __init__(self, *args, **kwargs):
        super(PasswordResetForm, self).__init__(*args, **kwargs)
        self.fields["email"].widget.attrs.update({"placeholder": "Email"})
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "email",
            Submit("submit", "Reset Password", css_class="btn-block btn-flat"),
        )


class SetPasswordForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super(SetPasswordForm, self).__init__(*args, **kwargs)
        self.fields["new_password1"].widget.attrs.update({"placeholder": "Password"})
        self.fields["new_password2"].widget.attrs.update(
            {"placeholder": "Confirm Password"}
        )
        self.fields["new_password1"].help_text = None
        self.fields["new_password2"].help_text = None
        self.helper = FormHelper()
        self.helper.form_show_labels = False
        self.helper.layout = Layout(
            "new_password1",
            "new_password2",
            Submit("submit", "Reset Password", css_class="btn-block btn-flat"),
        )


class UserTagForm(forms.ModelForm):
    class Meta:
        model = UserTag
        fields = ["name", "description", "color"]

    def __init__(self, user=None, *args, **kwargs):
        super(UserTagForm, self).__init__(*args, **kwargs)
        self.user = user
        self.helper = FormHelper()
        self.helper.layout = Layout(
            "name",
            "description",
            Div(
                Field("color", css_class="colorpicker"),
                Button(
                    "generate",
                    "Gen",
                    css_class="btn btn-default btn-flat",
                    css_id="genNew",
                ),
                HTML(
                    """<span class="label label-tag preview-tag" style="color: #fff; background-color: {{form.color.value}};">preview</span>"""
                ),
                css_class="form-inline form-group",
            ),
            FormActions(
                HTML(
                    """<a href="{% url 'tags' %}" class="btn btn-default">Cancel</a> """
                ),
                Submit("save", "Save"),
                css_class="pull-right",
            ),
        )
