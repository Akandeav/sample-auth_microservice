from rest_framework import serializers
from django.contrib.auth.models import User
from .models import UserData

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserData
        fields = ['id', 'firstname', 'lastname', 'email', 'password', 'UserRole']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance
class LoginSerializer(serializers.ModelSerializer):
    pass
    '''
    class Meta:
        model = User
        fields = '__all__'
    '''