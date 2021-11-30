from django.shortcuts import render

# Create your views here.
import requests
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from django.forms.utils import ErrorList
from django.http import HttpResponse
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import UserSerializer, LoginSerializer
from .forms import LoginForm, SignUpForm
from rest_framework.renderers import JSONRenderer
from rest_framework.parsers import JSONParser
from rest_framework.exceptions import AuthenticationFailed
from.models import UserData
#from .producer import publishUser
import jwt, datetime

secret = 'y>B+vd\7RkdrU~z`/r=6[LA3HR'

'''
User Signup API
/auth/signup
method: POST
data: {
    firstname: "",
    lastname: "",
    email: "",
    password: "",
} 
'''      
class SignupView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        token = GenerateVerLink.post(self, request)
        response = Response()
        message = "http://localhost:3000/auth/verify/" + str(token.data['token'])
        print(message)
        response.data = {
            'message': message
        }
        
        #publishUser('user_created', serializer.data)
        return response
class ChangePasswordLink(APIView):
    def post(self, request):
        email = request.data['email']
        token = GenerateVerLink.post(self, request)
        response = Response()
        message = "http://localhost:3000/auth/forgotpwd/" + str(token.data['token'])
        print(message)
        response.data = {
            'message': message
        }
        return response
'''
Generate email verification link API
/auth/gnt
method: POST
data: {
    email: ""
} 
'''  
class GenerateVerLink(APIView):
    def post(self, request):
        email = request.data['email']
        iat = datetime.datetime.utcnow()
        date = iat.date()
        time = iat.time()
        payload = {
                'email': request.data['email'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                'iat': datetime.datetime.utcnow()
            }

        token = jwt.encode(payload, secret, algorithm='HS256')
        response = Response()
        response.data = {
            'token': token
        }
        
        #publishUser('VerLink_created', serializer.data)
        return response

class VerifyToken(APIView):
    def post(self, request):
        token = request.data['B']
        

# User Verification /auth/verify

class VerifyEmail(APIView):
    def post(self, request):
        token  = request.data['B']
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            message = "Expired link"
            raise AuthenticationFailed('Link Expired')
        user = UserData.objects.get(email=payload['email'])
        if UserData.objects.filter(email=payload['email'], user_verification=0).first():
            user.user_verification = True
            user.save()
            message = "Success Email is Verified"
        elif UserData.objects.filter(email=payload['email'], user_verification=1).first():
            message = "Email already verified"
        response = Response()
        response.data = {
            'user': payload['email'],
            'message': message
            
        }
        return response

# Login /auth/signin

class LoginView(APIView):
    def post(self, request):
        email = request.data['email']
        password = request.data['password']
        user = UserData.objects.filter(email=email).first()
        v = UserData.objects.filter(email=email)
        

        if user is None:
            raise AuthenticationFailed('User not found!')
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password')
        
        if UserData.objects.filter(email=email, user_verification=0).first():
            raise AuthenticationFailed('User not verified')
        elif UserData.objects.filter(email=email, user_verification=1).first():
            payload = {
                'id': user.id,
                'role': user.UserRole,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
                'iat': datetime.datetime.utcnow()
            }

            token = jwt.encode(payload, secret, algorithm='HS256')

            response = Response()
            response.set_cookie(key='plt', value=token, httponly=True)
            response.data = {
                "token": token
            }
        return response

# Logout /auth/logout

class LogoutView(APIView):
    def post(self, request):
        response = Response()
        response.delete_cookie('plt')
        response.data = {
            'message': 'Logged out!'
        }
        return response

# Get active user info /auth/user

class UserView(APIView):
    def get(self, request):
        token  = request.COOKIES.get('plt')

        if not token:
            message = "no"
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unathenticated')
        user = UserData.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        message = "yes"
        response = Response()
        response.data = {
            "data": serializer.data,
            "message": message
        }
        return response

# active user change password /auth/changepwd

class ChangePassword(APIView):
    def post(self, request):
        password = request.data['password']
        token  = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('session expired')
        
        user = UserData.objects.filter(id=payload['id']).first()
        
        if not user.check_password(password):
            raise AuthenticationFailed('Incorrect password')
        
        user.set_password(request.data['new_password'])
        user.save()
        response = Response()
        response.delete_cookie('jwt')
        response.data= {
            'id': "Login again!"
        } 
        return response 

# Delete user 

class DeleteUserView(APIView):
    def delete(self, request):
        token  = request.COOKIES.get('jwt')
        email = request.data['email']
        payload = jwt.decode(token, secret, algorithms=['HS256'])
        user_role = payload['role']
        print(user_role)
        response = Response()
        if user_role == 'A':
            if not UserData.objects.filter(email=email):
                response.data = {
                'message': 'User does not exist',
                'user': email
                }
            else:
                UserData.objects.filter(email=email).delete()
                
                response.data = {
                    'message': 'User Deleted!',
                    'user': email
                }
        else:
            raise AuthenticationFailed('Unauthorized access!')
        return response

# Registered email query

class QueryEmail(APIView):
    def post(self, request):
        email = request.data['email']
        user = UserData.objects.filter(email=email)
        response = Response()
        if not user:
            response.data = {
                'message': 'yes'
            }
        else:
            response.data = {
                'message': 'no'
            }

        return response
    