from hashlib import sha224
from random import randint
from uuid import uuid4

from django.forms import ModelForm
from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from oidc_provider.models import Code, Token, RSAKey, Scope
from oidc_provider.lib.utils.common import get_client_model


class ClientForm(ModelForm):

    class Meta:
        model = get_client_model()
        exclude = []

    def __init__(self, *args, **kwargs):
        super(ClientForm, self).__init__(*args, **kwargs)
        self.fields['client_id'].required = False
        self.fields['client_id'].widget.attrs['disabled'] = 'true'
        self.fields['client_secret'].required = False
        self.fields['client_secret'].widget.attrs['disabled'] = 'true'

    def clean_client_id(self):
        instance = getattr(self, 'instance', None)
        if instance and instance.pk:
            return instance.client_id
        else:
            return str(randint(1, 999999)).zfill(6)

    def clean_client_secret(self):
        instance = getattr(self, 'instance', None)

        secret = ''

        if instance and instance.pk:
            if (self.cleaned_data['client_type'] == 'confidential') and not instance.client_secret:
                secret = sha224(uuid4().hex.encode()).hexdigest()
            elif (self.cleaned_data['client_type'] == 'confidential') and instance.client_secret:
                secret = instance.client_secret
        else:
            if (self.cleaned_data['client_type'] == 'confidential'):
                secret = sha224(uuid4().hex.encode()).hexdigest()

        return secret


@admin.register(get_client_model())
class ClientAdmin(admin.ModelAdmin):

    fieldsets = [
        [_(u''), {
            'fields': (
                'name', 'owner', 'client_type', 'response_types', '_redirect_uris', 'jwt_alg',
                'require_consent', 'reuse_consent'),
        }],
        [_(u'Credentials'), {
            'fields': ('client_id', 'client_secret', 'scope'),
        }],
        [_(u'Information'), {
            'fields': ('contact_email', 'website_url', 'terms_url', 'logo', 'date_created'),
        }],
        [_(u'Session Management'), {
            'fields': ('_post_logout_redirect_uris',),
        }],
    ]
    form = ClientForm
    list_display = ['name', 'client_id', 'response_type_descriptions', 'date_created']
    readonly_fields = ['date_created']
    search_fields = ['name']
    raw_id_fields = ['owner']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        
        defined_fields = set()
        for fieldset in self.fieldsets:
            defined_fields.update(fieldset[1]['fields'])

        # Obtiene todos los campos del modelo retornado por get_client_model
        dynamic_model_fields = set(field.name for field in self.model._meta.get_fields())

        # Compara y revisa si hay campos adicionales en el modelo usado
        additional_fields = dynamic_model_fields - defined_fields

        # Excluye campos "clientscope" e "id" si existen
        additional_fields = {
            field for field in additional_fields
            if field not in {'clientscope', 'id'}
        }

        # Incluye los campos adicionales
        if additional_fields:
            main_fields = list(self.fieldsets[0][1]['fields'])
            self.fieldsets[0][1]['fields'] = tuple(main_fields + list(additional_fields))


@admin.register(Code)
class CodeAdmin(admin.ModelAdmin):

    def has_add_permission(self, request):
        return False


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):

    def has_add_permission(self, request):
        return False


@admin.register(RSAKey)
class RSAKeyAdmin(admin.ModelAdmin):

    readonly_fields = ['kid']

@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    fieldsets = [
        [_(u''), {
            'fields': ('scope', 'description'),
        }]
    ]
    list_display = ('scope', 'description')
    search_fields = ['scope', 'description']
