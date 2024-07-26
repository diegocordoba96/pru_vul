from rest_framework import serializers
from ..models import vulnerabilities
from django.contrib.auth.models import User



class vulnerabilitySerealizer(serializers.ModelSerializer):
    class Meta:
        model = vulnerabilities
        fields = ('id', 'vul_id','fixeada', 'date_fixeada')
        read_only_fields = ('date_fixeada',)
        
        


class UserSerealizer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email' ,'password']
         