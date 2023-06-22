from django.contrib.auth import get_user_model
from django.db import models


class OIDCExtraData(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE)
    data = models.JSONField()

    def __str__(self):
        return str(self.user)
    
