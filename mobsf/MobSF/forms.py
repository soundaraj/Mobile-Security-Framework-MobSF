from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm

from mobsf.MobSF.models import Auth_user


class UploadFileForm(forms.Form):
    file = forms.FileField()


class FormUtil(object):

    def __init__(self, form):
        self.form = form

    @staticmethod
    def errors_message(form):
        """Form Errors.

        :param form forms.Form
        form.errors.get_json_data() django 2.0 or higher

        :return
        example
        {
        "error": {
            "file": "This field is required.",
            "test": "This field is required."
            }
        }
        """
        data = form.errors.get_json_data()
        for k, v in data.items():
            data[k] = ' '.join([value_detail['message'] for value_detail in v])
        return data

    @staticmethod
    def errors(form):
        return form.errors.get_json_data()


class RegistrationForm(UserCreationForm):
    email = forms.EmailField(max_length=60, help_text='Required. Add a valid email address')

    class Meta:
        model = Auth_user
        fields = ("email", "password1", "password2")

class LoginForm(forms.Form):
    email = forms.EmailField(max_length=60, help_text='Required. Add a valid email address')

    class Meta:
        fields = ("email", "password")