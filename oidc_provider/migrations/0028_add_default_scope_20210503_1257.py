# Generated by Django 3.0.2 on 2021-04-23 00:08

from django.db import migrations, models

def load_scope(apps, schema_editor):
    Scope = apps.get_model("oidc_provider", "Scope")
    OpenID_Scope = Scope(scope="openid", description="Provide access to openid endpoints")
    OpenID_Scope.save()
    Profile_Scope = Scope(scope="profile", description="Get Basic Profile from user info")
    Profile_Scope.save()
    Email_Scope = Scope(scope="email", description="Get email from user info")
    Email_Scope.save()
    Address_Scope = Scope(scope="address", description="Get address from user info")
    Address_Scope.save()
    Phone_Scope = Scope(scope="phone", description="Get phone from user info")
    Phone_Scope.save()
    Offline_Scope = Scope(scope="offline_access", description="Allow access to offline_access flow")
    Offline_Scope.save()
    Introspection_Scope = Scope(scope="token_introspection", description="Allow access to introspection endpoint")
    Introspection_Scope.save()

class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0027_add_scope_20210423_0008'),
    ]

    operations = [
        migrations.RunPython(load_scope),
    ]
