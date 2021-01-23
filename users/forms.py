from django.contrib.auth.forms import UserCreationForm, PasswordResetForm, PasswordChangeForm, SetPasswordForm, UserChangeForm
from django.forms.utils import ErrorList
from .models import User, Profile
from django import forms


class DivErrorList(ErrorList):
    def __str__(self):
        return self.as_divs()

    def as_divs(self):
        if not self: return ''
        return '<div class="errorlist">%s</div>' % ''.join(['<p class="error">%s</p>' % e for e in self])


class SignUpForm(UserCreationForm):
    first_name = forms.CharField(max_length=255, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Prénom'}))
    last_name = forms.CharField(max_length=255, widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}))

    class Meta:
        model = User
        fields = ('first_name', 'last_name', 'email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        super(SignUpForm, self).__init__(*args, **kwargs)

        self.fields['password1'].widget.attrs['class'] = 'form-control'
        self.fields['password1'].widget.attrs['placeholder'] = 'Mot de passe'
        self.fields['password2'].widget.attrs['class'] = 'form-control'
        self.fields['password2'].widget.attrs['placeholder'] = 'Confirmez le mot de passe'

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email):
            raise forms.ValidationError('Cet email est déjà utilisé. Veuillez recommencer.')
        elif email == '':
            raise forms.ValidationError('Vous devez renseigner votre adresse email.')
        return email

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('Les mots de passe ne correspondent pas. Veuillez les saisir à nouveau.')
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user


class LoginForm(forms.Form):
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Mot de passe'}))

    """class Meta:
        model = User
        fields = ('email', 'password')"""


class EmailForm(forms.Form):
    email = forms.EmailField(widget=forms.TextInput(attrs={'class': 'form-control',
                                                           'placeholder': 'Entrez votre email ici'}))


class ForgottenPasswordForm(SetPasswordForm):
    new_password1 = forms.CharField(label='', widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                      'placeholder': 'Nouveau mot de passe'}))

    new_password2 = forms.CharField(label='', widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                      'placeholder': 'Confirmez votre mot de passe'}))

    def clean_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('Les mots de passe ne correspondent pas. Veuillez les saisir à nouveau.')
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['new_password1'])
        if commit:
            user.save()
        return user


class NewPasswordForm(PasswordChangeForm):
    old_password = forms.CharField(label='', widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                               'placeholder': 'Mot de passe actuel'}))

    new_password1 = forms.CharField(label='', widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                                'placeholder': 'Nouveau mot de passe'}))

    new_password2 = forms.CharField(label='', widget=forms.PasswordInput(attrs={'class': 'form-control',
                                                                                'placeholder':
                                                                                    'Confirmez votre mot de passe'}))

    def clean_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('Les mots de passe ne correspondent pas. Veuillez les saisir à nouveau.')
        return password2

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['new_password1'])
        if commit:
            user.save()
        return user


class ProfileForm(UserChangeForm):
    first_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Prénom'}))
    last_name = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Nom'}))
    email = forms.EmailField(widget=forms.EmailInput(attrs={'class': 'form-control', 'placeholder': 'Email'}))
    ville = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Ville'}))
    pays = forms.CharField(widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Pays'}))
    bio = forms.CharField(widget=forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Bio et intérêts'}))
    #profile_pic = forms.ImageField(forms.Textarea(attrs={'class': 'form-control', 'placeholder': 'Cliquer pour changer l\'image'}))

    class Meta:
        model = Profile
        fields = ('email', 'first_name', 'last_name', 'ville', 'pays', 'bio', 'profile_pic')







