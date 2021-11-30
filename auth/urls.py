from django.contrib import admin
from django.urls import path
from .views import SignupView, LoginView, UserView, LogoutView, DeleteUserView, VerifyEmail, GenerateVerLink, ChangePassword, QueryEmail, ChangePasswordLink

urlpatterns = [
    path('signup', SignupView.as_view()),
    path('signin', LoginView.as_view()),
    path('user', UserView.as_view()),
    path('logout', LogoutView.as_view()),
    path('delete', DeleteUserView.as_view()),
    path('gnt', GenerateVerLink.as_view()),
    path('verify', VerifyEmail.as_view()),
    path('email-query', QueryEmail.as_view()),
    path('changepwd', ChangePassword.as_view()),
    path('pwdlink', ChangePasswordLink.as_view())
]

#Class based view on rest_framework viewsets.Viewset
'''
urlpatterns = [
    path('signup', UserCredentialsView.as_view({
        'post': 'register_user',
    })),
]
'''