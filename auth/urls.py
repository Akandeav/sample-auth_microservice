from django.contrib import admin
from django.urls import path
from .views import SignupView, LoginView, UserView, LogoutView, DeleteUserView, VerifyEmail, GenerateToken, ChangePassword, QueryEmail, ForgotPasswordLink, ForgotPassword, GenerateEmailLink

urlpatterns = [
    path('signup', SignupView.as_view()),
    path('signin', LoginView.as_view()),
    path('user', UserView.as_view()),
    path('logout', LogoutView.as_view()),
    path('delete', DeleteUserView.as_view()),
    path('generate.token', GenerateToken.as_view()),
    path('verify.email', VerifyEmail.as_view()),
    path('email.query', QueryEmail.as_view()),
    path('change.password', ChangePassword.as_view()),
    path('forgot.password.link', ForgotPasswordLink.as_view()),
    path('forgot.password', ForgotPassword.as_view()),
    path('generate.email.link', GenerateEmailLink.as_view())
]

#Class based view on rest_framework viewsets.Viewset
'''
urlpatterns = [
    path('signup', UserCredentialsView.as_view({
        'post': 'register_user',
    })),
]
'''