from django.db import models

# Create your models here.
class vulnerabilities(models.Model):
    vul_id = models.CharField(max_length=50)
    fixeada = models.BooleanField(default=False)
    date_fixeada = models.DateTimeField(auto_now_add=True)
    
    
    
