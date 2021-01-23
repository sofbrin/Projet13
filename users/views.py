from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404
from django.template.loader import render_to_string
from django.http import HttpResponseRedirect
from django.urls import reverse, reverse_lazy
from django.contrib.sites.shortcuts import get_current_site
from django.contrib import messages
from django.utils.encoding import force_text, force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.views import generic
from django.views.generic import DetailView

from .tokens import account_activation_token, password_reset_token
from django.core.mail import send_mail
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.views import PasswordChangeView
from django.contrib.auth.forms import PasswordChangeForm

from .models import User, Profile
from .forms import SignUpForm, LoginForm, EmailForm, ForgottenPasswordForm, NewPasswordForm, ProfileForm, DivErrorList


def signup_view(request):
    """ Rendering the registration form """
    if request.method == 'POST':
        print('REGISTER 0')
        form = SignUpForm(request.POST, error_class=DivErrorList)
        if form.is_valid():

            email = form.clean_email()
            form.clean_password2()
            user = form.save()
            user.is_active = False
            user.save()
            current_site = get_current_site(request)
            subject = 'Activez votre compte My French Platform'
            sender = 'sofbrin@gmail.com'
            message = render_to_string('registration/signup_activation.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': account_activation_token.make_token(user),
            })

            send_mail(subject, message, sender, [email])
            #to_email = EmailMessage(subject, message, to=[email])
            #to_email.send()
            #messages.add_message(request, messages.INFO, "Vous avez reçu un email pour finaliser l'inscription.")
            messages.info(request, "Vous avez reçu un email pour finaliser l'inscription.", extra_tags='toaster')
            return HttpResponseRedirect(reverse('home'))

    else:
        form = SignUpForm()

    return render(request, 'registration/signup.html', {'form': form, 'page_title': "S'inscrire"})


def signup_activation(request, uidb64, token):
    print('ACTIVATE 0')
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
        print('ACTIVATE 1')
    except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
        user = None
        print('ACTIVATE user = none')
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        print('ACTIVATE 2')
        messages.success(request, 'Vous êtes connecté.', extra_tags='toaster')
        return HttpResponseRedirect(reverse('home'))
    else:
        messages.error(request, "L'email n'est pas valide.", extra_tags='toaster')
        print('ACTIVATE return signup')
        return HttpResponseRedirect(reverse('signup'))


def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            email = request.POST['email']
            password = request.POST['password']
            user = authenticate(request, email=email, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    messages.success(request, 'Vous êtes connecté', extra_tags='toaster')
                    return HttpResponseRedirect(reverse('home'))
                else:
                    messages.info(request, 'Compte désactivé', extra_tags='toaster')
                    return HttpResponseRedirect(reverse('login'))
        messages.error(request, 'Vos identifiants sont invalides. Veuillez les saisir à nouveau', extra_tags='toaster')
                                     #"Veuillez saisir à nouveau vos identifiants ou créer un compte.")
        #messages.error(request, 'Erreur de saisie', extra_tags='toaster')
        return HttpResponseRedirect(reverse('login'))
    else:
        form = LoginForm()
        return render(request, 'registration/login.html', {'form': form, 'page_title': 'Se connecter'})


def logout_view(request):
    logout(request)
    messages.success(request, 'Vous êtes déconnecté', extra_tags='toaster')
    return HttpResponseRedirect(reverse('home'))


def forgot_password(request):
    if request.method == 'POST':
        form = EmailForm(request.POST, error_class=DivErrorList)
        if form.is_valid():
            email = request.POST.get('email')
            qs = User.objects.filter(email=email)
            current_site = get_current_site(request)
            subject = 'Changer le mot de passe de votre compte MyFrenchPlatform'
            sender = 'sofbrin@gmail.com'
            if len(qs) > 0:
                user = qs[0]
                user.is_active = False
                #user.reset_password = True
                user.save()

                message = render_to_string('registration/forgot_password_send_link.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                })

                send_mail(subject, message, sender, [email])
                # to_email = EmailMessage(subject, message, to=[email])
                # to_email.send()
                messages.add_message(request, messages.INFO, "Vous avez reçu un email pour finaliser l'inscription.")
                # messages.info(request, "Vous avez reçu un email pour finaliser l'inscription.", extra_tags='toaster')
                return HttpResponseRedirect(reverse('home'))

    else:
        form = EmailForm()

    return render(request, 'registration/forgot_password_enter_email.html', {'form': form, 'page_title': "Mot de passe oublié"})


def forgot_password_activation(request, uidb64, token):
    print('RESET 0')
    if request.method == 'POST':
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            print('RESET 1')
        except (TypeError, ValueError, OverflowError, ObjectDoesNotExist):
            user = None
            print('RESET user = none')
        if user is not None and password_reset_token.check_token(user, token):
            form = ForgottenPasswordForm(user=user, data=request.POST)
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, form.user)

                user.is_active = True
                #user.reset_password = False
                user.save()
                #login(request, user)

                messages.success(request, 'Le mot de passe a bien été changé.', extra_tags='toaster')
                return HttpResponseRedirect(reverse('login'))
            else:
                messages.error(request, 'Corriger l\'erreur')
                #context = {'form': form, 'uid': uidb64, 'token': token}
                #return render(request, 'users/reset_forgotten_password', context)
        else:
            #messages.error(request, "L'email n'est pas valide.", extra_tags='toaster')
            print('RESET return reset')
            return HttpResponseRedirect(reverse('reset_password'))
    else:
        form = ForgottenPasswordForm(request.user)

    return render(request, 'registration/forgot_password_page.html', {'form': form, 'page_title': 'Changer le mot de passe'})


@login_required
def change_password(request):
    if request.method == 'POST':
        form = NewPasswordForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            return HttpResponseRedirect(reverse('home'))
        else:
            messages.error(request, 'Corriger l\'erreur')
    else:
        form = NewPasswordForm(request.user)
    return render(request, 'registration/change_password_page.html', {'form': form, 'page_title': 'Changer le mot de passe'})


def edit_profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST, instance=request.user)

        if form.is_valid():
            form.save()
            print('sauvegardé dans db')
            return HttpResponseRedirect(reverse('edit_profile_page'))
    else:
        form = ProfileForm(instance=request.user)
        context = {'form': form, 'page_title': 'Profil'}
        return render(request, 'registration/edit_profile_page.html', context)
