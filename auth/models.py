from django.db import models
from django.contrib.auth.models import AbstractUser

# Create your models here.
class UserData(AbstractUser):
    
    PUBLIC = 'P'
    AUTHOR = 'A'
    REVIEWER = 'R'
    
    USER_ROLES = [
        (PUBLIC, 'public'),
        (AUTHOR, 'author'),
        (REVIEWER, 'reviewer'),   
    ]
    username = None
    password = models.CharField(max_length=200)
    email = models.EmailField(max_length=100, unique=True)
    firstname = models.CharField(max_length=20)
    lastname = models.CharField(max_length=20)
    UserRole = models.CharField(max_length=2, choices=USER_ROLES, default=PUBLIC)
    user_verification = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []