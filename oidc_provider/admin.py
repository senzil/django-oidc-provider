from hashlib import sha224
from random import randint
from typing import Optional, TypeVar
from uuid import uuid4

from django.http.request import HttpRequest
from django.db.models.base import Model
from django.forms import ModelForm
from django.contrib import admin
from django.utils.translation import ugettext_lazy as _

from .models import Client, Code, JWEPrivateKey, Token, JWSKey, Scope

_ModelT = TypeVar("_ModelT", bound=Model)


class ClientForm(ModelForm):
    class Meta:
        model = Client
        exclude = []

    def __init__(self, *args, **kwargs):
        super(ClientForm, self).__init__(*args, **kwargs)
        self.fields["client_id"].required = False
        self.fields["client_id"].widget.attrs["disabled"] = "true"
        self.fields["client_secret"].required = False
        self.fields["client_secret"].widget.attrs["disabled"] = "true"

    def clean_client_id(self):
        instance = getattr(self, "instance", None)
        if instance and instance.pk:
            return instance.client_id
        else:
            return str(randint(1, 999999)).zfill(6)

    def clean_client_secret(self):
        instance = getattr(self, "instance", None)

        secret = ""

        if instance and instance.pk:
            if (
                self.cleaned_data["client_type"] == "confidential"
            ) and not instance.client_secret:
                secret = sha224(uuid4().hex.encode()).hexdigest()
            elif (
                self.cleaned_data["client_type"] == "confidential"
            ) and instance.client_secret:
                secret = instance.client_secret
        else:
            if self.cleaned_data["client_type"] == "confidential":
                secret = sha224(uuid4().hex.encode()).hexdigest()

        return secret


@admin.register(Client)
class ClientAdmin(admin.ModelAdmin):

    fieldsets = [
        [
            _(""),
            {
                "fields": (
                    "name",
                    "owner",
                    "client_type",
                    "response_types",
                    "_redirect_uris",
                    "require_consent",
                    "reuse_consent",
                ),
            },
        ],
        [
            _("Id Token"),
            {
                "fields": (
                    "idtoken_alg",
                    "idtoken_jwk_type",
                    "idtoken_jwe_alg",
                    "idtoken_jwe_enc",
                ),
            },
        ],
        [
            _("Access Token"),
            {"fields": ("at_alg", "at_jwk_type", "at_jwe_alg", "at_jwe_enc")},
        ],
        [
            _("Refresh Token"),
            {"fields": ("rt_alg", "rt_jwk_type", "rt_jwe_alg", "rt_jwe_enc")},
        ],
        [
            _("Credentials"),
            {
                "fields": ("client_id", "client_secret", "scope"),
            },
        ],
        [
            _("Information"),
            {
                "fields": (
                    "contact_email",
                    "website_url",
                    "terms_url",
                    "logo",
                    "date_created",
                ),
            },
        ],
        [
            _("Session Management"),
            {
                "fields": ("_post_logout_redirect_uris",),
            },
        ],
    ]
    form = ClientForm
    list_display = ["name", "client_id", "response_type_descriptions", "date_created"]
    readonly_fields = ["date_created"]
    search_fields = ["name"]
    raw_id_fields = ["owner"]


@admin.register(Code)
class CodeAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False


@admin.register(JWSKey)
class JWSAdmin(admin.ModelAdmin):

    change_list_template = "admin/change_list_jwkkeys.html"

    fieldsets = [
        [
            _(""),
            {
                "fields": ("key_type", "valid_from", "expires_at"),
            },
        ]
    ]

    list_display = ["kid", "key_type", "valid_from", "has_expired"]

    readonly_fields = ["kid", "has_expired"]

    def has_change_permission(
        self, request: HttpRequest, obj: Optional[_ModelT] = ...
    ) -> bool:
        return False


@admin.register(JWEPrivateKey)
class JWEAdmin(admin.ModelAdmin):

    change_list_template = "admin/change_list_jwkkeys.html"

    fieldsets = [
        [
            _(""),
            {
                "fields": ("key_type", "valid_from", "expires_at"),
            },
        ]
    ]

    list_display = ["kid", "key_type", "valid_from", "has_expired"]

    readonly_fields = ["kid", "has_expired"]

    def has_change_permission(
        self, request: HttpRequest, obj: Optional[_ModelT] = ...
    ) -> bool:
        return False


@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    fieldsets = [
        [
            _(""),
            {
                "fields": ("scope", "description"),
            },
        ]
    ]
    list_display = ("scope", "description")
    search_fields = ["scope", "description"]
