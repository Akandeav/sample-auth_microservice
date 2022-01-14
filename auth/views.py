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

secret = ' '

      
class SignupView(APIView):
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
    Returns signup status
    '''
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        token = GenerateToken.post(self, request)
        response = Response()
        message = "http://localhost:3000/auth/verify/" + str(token.data['token'])
        print(message) #For test purpose only, ideally request is sent to Notification service
        response.data = {
            "ok": True,
            'message': message
        }
        
        #publishUser('user_created', serializer.data)
        return response

class ForgotPasswordLink(APIView):
    """
    Generate a forgot password link
    /auth/forgot.password.link

    Returns a password reset link
    """
    def post(self, request):
        email = request.data['email']
        token = GenerateToken.post(self, request)
        print(email)
        response = Response()
        message = "http://localhost:3000/auth/forgotpwd/" + str(token.data['token'])
        print(message) # For test purposes only. Ideal situation link is sent to Notification service
        response.data = {
            "ok": True,
            'message': message
        }
        return response
 
class GenerateToken(APIView):
    """
    Generates web token, for internal calls only

    Returns a web token
    """
    def post(self, request):
        email = request.data['email']
        payload = {
                'email': email,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                'iat': datetime.datetime.utcnow()
            }

        token = jwt.encode(payload, secret, algorithm='HS256')
        response = Response()
        response.data = {
            "ok": True,
            'token': token
        }
        
        #publishUser('VerLink_created', serializer.data)
        return response

class GenerateEmailLink(APIView):
    '''
    Generate email verification link API
    /auth/generate.email.link
    method: POST
    data: {
        email: ""
    }
    
    Returns status: True or False
    ''' 
    def post(self, request):
        email = request.data['email']
        print(email)
        message=''
        
        if (UserData.objects.filter(email=email, user_verification=1)): #User is already verified
            ok = False
        else:
            payload = {
                    'email': email,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30),
                    'iat': datetime.datetime.utcnow()
                }
            
            token = jwt.encode(payload, secret, algorithm='HS256')
            message = "http://localhost:3000/auth/verify/" + str(token) # For test purposes only. Ideal situation link is sent to Notification service
            print(message)
            ok = True
        
        response = Response()
        response.data = {
            "ok": ok,
            'message': message
        }
        
        
        
        
        #publishUser('VerLink_created', serializer.data)
        return response

class VerifyEmail(APIView):
    """
    Verifies a user's email
    /auth/verify.email
    
    Returns status
    """
    def post(self, request):
        token  = request.data['B']
        if not token:
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            message = False
            raise AuthenticationFailed('Link Expired')
        user = UserData.objects.get(email=payload['email'])
        if UserData.objects.filter(email=payload['email'], user_verification=0).first():
            user.user_verification = True
            user.save()
            message = True
        elif UserData.objects.filter(email=payload['email'], user_verification=1).first():
            message = False
        response = Response()
        response.data = {
            'user': payload['email'],
            'ok': message
            
        }
        return response

class LoginView(APIView):
    """
    User Login
    /auth/signin

    Returns status and web token
    """
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
                "ok": True,
                "token": token
            }
        return response

class LogoutView(APIView):
    """
    Delete user token
    /auth/logout

    Returns True
    """
    def post(self, request):
        response = Response()
        response.delete_cookie('plt')
        response.data = {
            'ok': True
        }
        return response

class UserView(APIView):
    """
    Gets logged in user information
    /auth/user

    Returns JSON with user data
    """
    def get(self, request):
        token  = request.COOKIES.get('plt')

        if not token:
            message = False
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unathenticated')
        user = UserData.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)
        message = True
        response = Response()
        response.data = {
            "data": serializer.data,
            "ok": message
        }
        return response

class ForgotPassword(APIView):
    """
    Change user password.
    Requires token
    /auth/forgot.password

    Returns status
    """
    def post(self, request):
        password = request.data['password']
        token  = request.data['id']
        if not token:
            message = False
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            message = False
            raise AuthenticationFailed('session expired')
        
        user = UserData.objects.filter(email=payload['email']).first()
        user.set_password(request.data['password'])
        user.save()
        message = True
        response = Response()
        
        response.data= {
            "ok": message
        } 
        return response

class ChangePassword(APIView):
    """
    Allows user to change password
    requires user token
    /auth/change.password

    Returns status
    """
    def post(self, request):
        password = request.data['password']
        token  = request.COOKIES.get('plt')

        if not token:
            message = False
            raise AuthenticationFailed('Unauthenticated')
        try:
            payload = jwt.decode(token, secret, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            message = False
            raise AuthenticationFailed('session expired')
        
        user = UserData.objects.filter(id=payload['id']).first()
        
        if not user.check_password(password):
            message = False
            raise AuthenticationFailed('Incorrect password')
        
        user.set_password(request.data['new_password'])
        user.save()
        message = True
        response = Response()
        response.delete_cookie('jwt')
        response.data= {
            'ok': message
        } 
        return response 

class DeleteUserView(APIView):
    """
    Delete a user from database
    requires admin role
    /auth/delete

    Returns status
    """
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

class QueryEmail(APIView):
    """
    Queries database if an email is already registered or verified
    /auth/verify.email

    Returns status
    """
    def post(self, request):
        email = request.data['email']
        user = UserData.objects.filter(email=email)
        response = Response()
        if not user:
            response.data = {
                'message': 'yes'
            }
        else:
            if (UserData.objects.filter(email=email, user_verification=0)):
                uv = False
                response.data = {
                    'message': 'no',
                    "verified": uv
                }
            else:
                uv = True
                response.data = {
                    'message': 'no',
                    "verified": uv
                }
        return response
    