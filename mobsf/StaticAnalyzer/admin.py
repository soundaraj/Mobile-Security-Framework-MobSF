from django.contrib import admin

from mobsf.MobSF.models import Auth_user, pricingModel, userPricingModel

admin.site.register(Auth_user)
admin.site.register(pricingModel)
admin.site.register(userPricingModel)