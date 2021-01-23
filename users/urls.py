from django.urls import path
from . import views


urlpatterns = [
    path('signup', views.signup_view, name='signup'),
    path('email_activation/<uidb64>/<token>/', views.signup_activation, name='activate'),
    path('login', views.login_view, name='login'),
    path('logout', views.logout_view, name='logout'),
    path('forgot_password', views.forgot_password, name='forgot_password'),
    path('reset_forgotten_password/<uidb64>/<token>/', views.forgot_password_activation, name='reset_forgotten_password'),
    path('change_password', views.change_password, name='change_password'),
    path('edit_profile_page', views.edit_profile, name='edit_profile_page'),

]