# -*- coding: utf-8 -*-
from abc import abstractmethod
import base64
import binascii
from hashlib import sha256
import json
from typing import Any, Iterable, Optional

from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from jwt import InvalidAlgorithmError
from jwcrypto.jwk import JWK, JWKSet

from .lib.errors import JWEPrivateError

JWK_TYPE_CHOICES = [
    ("OCT128", "(OCT128) 128 bit symmetric key"),
    ("OCT256", "(OCT256) 256 bit symmetric key"),
    ("OCT384", "(OCT384) 384 bit symmetric key"),
    ("OCT512", "(OCT512) 512 bit symmetric key"),
    ("RSA2048", "(RSA2048) RSA 2048 bits"),
    ("RSA3072", "(RSA3072) RSA 3072 bits"),
    ("RSA4096", "(RSA4096) RSA 4096 bits"),
    ("EC256", "(EC256) Elliptic Curve using P-256"),
    ("EC384", "(EC384) Elliptic Curve using P-384"),
    ("EC521", "(EC521) Elliptic Curve using P-521"),
    ("ECsecp256k1", "(ECsecp256k1) Elliptic Curve using secp256k1"),
    ("OKPEd25519", "(OKPEd25519) Edwards Curve using Ed25519"),
    ("OKPEd448", "(OKPEd448) Edwards Curve using Ed448"),
    ("OKPX25519", "(OKPX25519) Edwards Curve using X25519"),
    ("OKPX448", "(OKPX448) Edwards Curve using X448"),
]

JWE_ALG_CHOICES = [
    ("RSA-OAEP", "(RSA-OAEP) RSAES OAEP using default parameters"),
    ("RSA-OAEP-256", "(RSA-OAEP-256) RSAES OAEP using SHA-256 and MGF1 with SHA-256"),
    ("A128KW", "(A128KW) AES Key Wrap with default initial value using 128 bit key"),
    ("A192KW", "(A192KW) AES Key Wrap with default initial value using 192 bit key"),
    ("A256KW", "(A256KW) AES Key Wrap with default initial value using 256 bit key"),
    ("dir", "Direct use of a shared symmetric key as the CEK"),
    (
        "ECDH-ES",
        "Elliptic Curve Diffie-Hellman Ephemeral Static key agreement using Concat KDF",
    ),
    ("ECDH-ES+A128KW", "ECDH-ES using Concat KDF and CEK wrapped with A128KW"),
    ("ECDH-ES+A192KW", "ECDH-ES using Concat KDF and CEK wrapped with A192KW"),
    ("ECDH-ES+A256KW", "ECDH-ES using Concat KDF and CEK wrapped with A256KW"),
    ("A128GCMKW", "Key wrapping with AES GCM using 128 bit key"),
    ("A192GCMKW", "Key wrapping with AES GCM using 192 bit key"),
    ("A256GCMKW", "Key wrapping with AES GCM using 256 bit key"),
    ("PBES2-HS256+A128KW", "PBES2 with HMAC SHA-256 and A128KW wrapping"),
    ("PBES2-HS384+A192KW", "PBES2 with HMAC SHA-384 and A192KW wrapping"),
    ("PBES2-HS512+A256KW", "PBES2 with HMAC SHA-512 and A256KW wrapping"),
]

JWE_ENC_CHOICES = [
    ("A128CBC-HS256", "AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm"),
    ("A192CBC-HS384", "AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm"),
    ("A256CBC-HS512", "AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm"),
    ("A128GCM", "AES GCM using 128 bit key"),
    ("A192GCM", "AES GCM using 192 bit key"),
    ("A256GCM", "AES GCM using 256 bit key"),
]

JWS_ALG_CHOICES = [
    ("HS256", "(HS256) HMAC using SHA-256"),
    ("HS384", "(HS384) HMAC using SHA-384"),
    ("HS512", "(HS512) HMAC using SHA-512"),
    ("RS256", "(RS256) RSASSA-PKCS-v1_5 using SHA-256"),
    ("RS384", "(RS384) RSASSA-PKCS-v1_5 using SHA-384"),
    ("RS512", "(RS512) RSASSA-PKCS-v1_5 using SHA-512"),
    ("ES256", "(ES256) ECDSA using P-256 and SHA-256"),
    ("ES384", "(ES384) ECDSA using P-384 and SHA-384"),
    ("ES512", "(ES512) ECDSA using P-521 and SHA-512"),
    ("PS256", "(PS256) RSASSA-PSS using SHA-256 and MGF1 with SHA-256"),
    ("PS384", "(PS384) RSASSA-PSS using SHA-384 and MGF1 with SHA-384"),
    ("PS512", "(PS512) RSASSA-PSS using SHA-512 and MGF1 with SHA-512"),
    ("none ", "(none) No digital signature or MAC performed"),
]

CLIENT_TYPE_CHOICES = [
    ("confidential", "Confidential"),
    ("public", "Public"),
]

RESPONSE_TYPE_CHOICES = [
    ("none", "none (Authorization None Flow)"),
    ("code", "code (Authorization Code Flow)"),
    ("token", "token (Authorization Token Flow)"),
    ("id_token", "id_token (Implicit Flow)"),
    ("id_token token", "id_token token (Implicit Flow)"),
    ("code token", "code token (Hybrid Flow)"),
    ("code id_token", "code id_token (Hybrid Flow)"),
    ("code id_token token", "code id_token token (Hybrid Flow)"),
]

GRANT_TYPES_CHOICES = [
    "implicit",
    "authorization_code",
    "client_credentials",
    "password",
    "refresh_token",
]

JWT_ALGS = [
    ("HS256", "HS256"),
    ("RS256", "RS256"),
]

JWT_ALGS_AT = [
    ("Opaque", "None"),
    ("HS256", "HS256"),
    ("RS256", "RS256"),
]


class Scope(models.Model):

    scope = models.CharField(max_length=30, primary_key=True, verbose_name=_("Scope"))
    description = models.CharField(
        max_length=50,
    )

    class Meta:
        verbose_name = _("Scope")
        verbose_name_plural = _("Scopes")

    def __str__(self):
        return f"{self.scope}"

    def __unicode__(self):
        return self.__str__()


class ResponseTypeManager(models.Manager):
    def get_by_natural_key(self, value):
        return self.get(value=value)


class ResponseType(models.Model):
    objects = ResponseTypeManager()

    value = models.CharField(
        max_length=30,
        choices=RESPONSE_TYPE_CHOICES,
        unique=True,
        verbose_name=_("Response Type Value"),
    )
    description = models.CharField(
        max_length=50,
    )

    def natural_key(self):
        return (self.value,)  # natural_key must return tuple

    def __str__(self):
        return f"{self.description}"


class Client(models.Model):

    name = models.CharField(max_length=100, default="", verbose_name=_("Name"))
    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        verbose_name=_("Owner"),
        blank=True,
        null=True,
        default=None,
        on_delete=models.SET_NULL,
        related_name="oidc_clients_set",
    )
    client_type = models.CharField(
        max_length=30,
        choices=CLIENT_TYPE_CHOICES,
        default="confidential",
        verbose_name=_("Client Type"),
        help_text=_(
            "<b>Confidential</b> clients are capable of maintaining the confidentiality"
            " of their credentials. <b>Public</b> clients are incapable."
        ),
    )
    client_id = models.CharField(max_length=255, unique=True, verbose_name=_("Client ID"))
    client_secret = models.CharField(max_length=255, blank=True, verbose_name=_("Client SECRET"))
    response_types = models.ManyToManyField(ResponseType)

    idtoken_alg = models.CharField(
        max_length=10,
        choices=JWT_ALGS,
        default="RS256",
        verbose_name=_("JWT Algorithm"),
        help_text=_("Algorithm used to encode ID Tokens."),
    )
    idtoken_jwk_type = models.CharField(
        max_length=11,
        choices=JWK_TYPE_CHOICES,
        default="RSA4096",
        verbose_name=_("JWKKey to Sign the JWT Id Token"),
        help_text=_("JWKKey to Sign the JWT Id Token headers."),
    )
    idtoken_jwe_alg = models.CharField(
        null=True,
        max_length=18,
        choices=JWE_ALG_CHOICES,
        default="A128KW",
        verbose_name=_("JWE Algorithm to Encrypt"),
        help_text=_("Algorithm used to encrypt ID Tokens."),
    )
    idtoken_jwe_enc = models.CharField(
        null=True,
        max_length=13,
        choices=JWE_ENC_CHOICES,
        default="A128CBC-HS256",
        verbose_name=_("JWE Algorithm to Encode"),
        help_text=_("Algorithm used to encrypt ID Tokens."),
    )

    at_alg = models.CharField(
        null=True,
        max_length=10,
        choices=JWT_ALGS_AT,
        default="RS256",
        verbose_name=_("Access Token JWT Algorithm"),
        help_text=_("Algorithm used to encode Access Tokens."),
    )
    at_jwk_type = models.CharField(
        null=True,
        max_length=11,
        choices=JWK_TYPE_CHOICES,
        default="RSA4096",
        verbose_name=_("JWKKey to Sign the JWT Access Token"),
        help_text=_("JWKKey to Sign the JWT Access Token."),
    )
    at_jwe_alg = models.CharField(
        null=True,
        max_length=18,
        choices=JWE_ALG_CHOICES,
        default=None,
        verbose_name=_("JWE Algorithm to Encrypt"),
        help_text=_("Algorithm used to encrypt Access Token."),
    )
    at_jwe_enc = models.CharField(
        null=True,
        max_length=13,
        choices=JWE_ENC_CHOICES,
        default=None,
        verbose_name=_("JWE Algorithm to Encode"),
        help_text=_("Algorithm used to encodeNoDataAllowedErr JWE Access Tokens."),
    )

    rt_alg = models.CharField(
        null=True,
        max_length=10,
        choices=JWT_ALGS_AT,
        default="RS256",
        verbose_name=_("Refresh Token JWT Algorithm"),
        help_text=_("Algorithm used to encode Refresh Tokens."),
    )
    rt_jwk_type = models.CharField(
        null=True,
        max_length=11,
        choices=JWK_TYPE_CHOICES,
        default="RSA4096",
        verbose_name=_("JWKKey to Sign the JWT Refresh Token"),
        help_text=_("JWKKey to Sign the JWT Refresh Token."),
    )
    rt_jwe_alg = models.CharField(
        null=True,
        max_length=18,
        choices=JWE_ALG_CHOICES,
        default=None,
        verbose_name=_("JWE Algorithm to Encrypt"),
        help_text=_("Algorithm used to encrypt Refresh Token."),
    )
    rt_jwe_enc = models.CharField(
        null=True,
        max_length=13,
        choices=JWE_ENC_CHOICES,
        default=None,
        verbose_name=_("JWE Algorithm to Encode"),
        help_text=_("Algorithm used to encode JWE Refresh Tokens."),
    )

    _redirect_uris = models.TextField(
        default="",
        verbose_name=_("Redirect URIs"),
        help_text=_("Enter each URI on a new line."),
    )

    scope = models.ManyToManyField(
        Scope,
        blank=True,
        default=None,
        verbose_name=_("Scopes"),
        help_text=_("Specifies the authorized scope values for the client app."),
    )

    date_created = models.DateField(auto_now_add=True, verbose_name=_("Date Created"))
    website_url = models.CharField(max_length=255, blank=True, default="", verbose_name=_("Website URL"))
    terms_url = models.CharField(
        max_length=255,
        blank=True,
        default="",
        verbose_name=_("Terms URL"),
        help_text=_("External reference to the privacy policy of the client."),
    )
    contact_email = models.CharField(max_length=255, blank=True, default="", verbose_name=_("Contact Email"))
    logo = models.FileField(
        blank=True,
        default="",
        upload_to="oidc_provider/clients",
        verbose_name=_("Logo Image"),
    )
    reuse_consent = models.BooleanField(
        default=True,
        verbose_name=_("Reuse Consent?"),
        help_text=_(
            "If enabled, server will save the user consent given to a specific client, "
            "so that user won't be prompted for the same authorization multiple times."
        ),
    )
    require_consent = models.BooleanField(
        default=True,
        verbose_name=_("Require Consent?"),
        help_text=_("If disabled, the Server will NEVER ask the user for consent."),
    )

    _post_logout_redirect_uris = models.TextField(
        blank=True,
        default="",
        verbose_name=_("Post Logout Redirect URIs"),
        help_text=_("Enter each URI on a new line."),
    )

    class Meta:
        verbose_name = _("Client")
        verbose_name_plural = _("Clients")

    def __str__(self):
        return f"{self.name}"

    def __unicode__(self):
        return self.__str__()

    def response_type_values(self):
        return (response_type.value for response_type in self.response_types.all())

    def response_type_descriptions(self):
        # return as a list, rather than a generator, so descriptions display correctly in admin
        return [response_type.description for response_type in self.response_types.all()]

    @property
    def redirect_uris(self):
        return self._redirect_uris.splitlines()

    @redirect_uris.setter
    def redirect_uris(self, value):
        self._redirect_uris = "\n".join(value)

    @property
    def post_logout_redirect_uris(self):
        return self._post_logout_redirect_uris.splitlines()

    @post_logout_redirect_uris.setter
    def post_logout_redirect_uris(self, value):
        self._post_logout_redirect_uris = "\n".join(value)

    @property
    def _scope(self):
        return " ".join(map(str, self.scope.values_list("scope", flat=True)))

    #   @scope.setter
    #   def scope(self, value):
    #       self.scope = value

    @property
    def default_redirect_uri(self):
        return self.redirect_uris[0] if self.redirect_uris else ""


class BaseCodeTokenModel(models.Model):

    client = models.ForeignKey(Client, verbose_name=_("Client"), on_delete=models.CASCADE)
    expires_at = models.DateTimeField(verbose_name=_("Expiration Date"))
    _scope = models.TextField(default="", verbose_name=_("Scopes"))

    class Meta:
        abstract = True

    @property
    def scope(self):
        return self._scope.split()

    @scope.setter
    def scope(self, value):
        self._scope = " ".join(value)

    def __unicode__(self):
        return self.__str__()

    def has_expired(self):
        return timezone.now() >= self.expires_at


class Code(BaseCodeTokenModel):

    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_("User"), on_delete=models.CASCADE)
    code = models.CharField(max_length=255, unique=True, verbose_name=_("Code"))
    nonce = models.CharField(max_length=255, blank=True, default="", verbose_name=_("Nonce"))
    is_authentication = models.BooleanField(default=False, verbose_name=_("Is Authentication?"))
    code_challenge = models.CharField(max_length=255, null=True, verbose_name=_("Code Challenge"))
    code_challenge_method = models.CharField(max_length=255, null=True, verbose_name=_("Code Challenge Method"))

    class Meta:
        verbose_name = _("Authorization Code")
        verbose_name_plural = _("Authorization Codes")

    def __str__(self):
        return f"{self.client} - {self.code}"


class Token(BaseCodeTokenModel):

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        verbose_name=_("User"),
        on_delete=models.CASCADE,
    )
    access_token = models.CharField(max_length=255, unique=True, verbose_name=_("Access Token"))
    refresh_token = models.CharField(max_length=255, unique=True, verbose_name=_("Refresh Token"))
    _id_token = models.TextField(verbose_name=_("ID Token"))

    class Meta:
        verbose_name = _("Token")
        verbose_name_plural = _("Tokens")

    @property
    def id_token(self):
        return json.loads(self._id_token) if self._id_token else None

    @id_token.setter
    def id_token(self, value):
        self._id_token = json.dumps(value)

    def __str__(self):
        return "{0} - {1}".format(self.client, self.access_token)

    @property
    def at_hash(self):
        # @@@ d-o-p only supports 256 bits (change this if that changes)
        hashed_access_token = sha256(self.access_token.encode("ascii")).hexdigest().encode("ascii")
        return (
            base64.urlsafe_b64encode(binascii.unhexlify(hashed_access_token[: len(hashed_access_token) // 2]))
            .rstrip(b"=")
            .decode("ascii")
        )


class UserConsent(BaseCodeTokenModel):

    user = models.ForeignKey(settings.AUTH_USER_MODEL, verbose_name=_("User"), on_delete=models.CASCADE)
    date_given = models.DateTimeField(verbose_name=_("Date Given"))

    class Meta:
        unique_together = ("user", "client")


class JWKKey(models.Model):

    date_created = models.DateField(auto_now_add=True, verbose_name=_("Date Created"))
    key_type = models.CharField(
        max_length=30,
        choices=JWK_TYPE_CHOICES,
        default="ES256",
        verbose_name=_("Key Type"),
        help_text=_("Specifies the cryptographic asymetric algorithms to sign the JWT Tokens"),
    )
    key = models.TextField(blank=False, verbose_name=_("Key"), help_text=_("Paste your private Key here."))
    valid_from = models.DateTimeField(default=timezone.now, verbose_name=_("Valid From"))
    expires_at = models.DateTimeField(blank=True, default=None, null=True, verbose_name=_("Expiration Date"))

    def save(
        self,
        force_insert: bool = False,
        force_update: bool = False,
        using: Optional[str] = None,
        update_fields: Optional[Iterable[str]] = None,
    ) -> None:
        self.__generate_key()
        return super().save(force_insert, force_update, using, update_fields)

    def delete(self, using: Any = None, keep_parents: bool = False) -> None:
        self.expires_at = timezone.now()
        self.save()

    __key_generators = {
        "OCT128": lambda: JWK.generate(kty="oct", size=128),
        "OCT256": lambda: JWK.generate(kty="oct", size=256),
        "OCT384": lambda: JWK.generate(kty="oct", size=384),
        "OCT512": lambda: JWK.generate(kty="oct", size=512),
        "RSA2048": lambda: JWK.generate(kty="RSA", size=2048),
        "RSA3072": lambda: JWK.generate(kty="RSA", size=3072),
        "RSA4096": lambda: JWK.generate(kty="RSA", size=4096),
        "EC256": lambda: JWK.generate(kty="EC", crv="P-256"),
        "EC384": lambda: JWK.generate(kty="EC", crv="P-384"),
        "EC521": lambda: JWK.generate(kty="EC", crv="P-521"),
        "ECsecp256k1": lambda: JWK.generate(kty="EC", crv="secp256k1"),
        "OKPEd25519": lambda: JWK.generate(kty="OKP", crv="Ed25519"),
        "OKPEd448": lambda: JWK.generate(kty="OKP", crv="Ed448"),
        "OKPX25519": lambda: JWK.generate(kty="OKP", crv="X25519"),
        "OKPX448": lambda: JWK.generate(kty="OKP", crv="X448"),
    }

    def __generate_key(self):
        if not self.key:
            key = self.__key_generators.get(
                self.key_type,
                lambda: (_ for _ in ()).throw(InvalidAlgorithmError(self.key_type)),
            )()
            key["kid"] = key.thumbprint()
            key = self.__custom_key_generator(key)
            self.key = key.export()

    @abstractmethod
    def __custom_key_generator(self, key):
        return key

    class Meta:
        verbose_name = _("JWK Key")
        verbose_name_plural = _("JWK Keys")
        abstract = True

    def __str__(self):
        return "{0}".format(self.kid)

    def __unicode__(self):
        return self.__str__()

    @property
    def jwk(self):
        return JWK.from_json(self.key)

    @property
    def kid(self):
        return self.jwk.thumbprint()

    def has_expired(self):
        return self.expires_at is not None and timezone.now() >= self.expires_at

    @classmethod
    def keyset(cls):
        jwkset = JWKSet()
        for jwkkey in [JWK.from_json(key) for key in cls.objects.all().values_list("key", flat=True)]:
            jwkset.add(jwkkey)
        return jwkset

    @classmethod
    def keyset_public(cls):
        jwkset = JWKSet()
        for jwkkey in [JWK.from_json(key) for key in cls.objects.all().values_list("key", flat=True)]:
            if jwkkey.has_public:
                jwkset.add(jwkkey)
        return jwkset


# Model to save all keys used for sign JWT
class JWSKey(JWKKey):
    def __custom_key_generator(self, key):
        key["use"] = "sig"
        return super().__custom_key_generator(key)


# Model to save all private keys used for read chipered JWT
# Is necesary don't export the private key, just the public
class JWEPrivateKey(JWKKey):
    def __custom_key_generator(self, key):
        key["use"] = "enc"
        return super().__custom_key_generator(key)


# Created or imported keys to cipher JWT to ensure that only the receiver can read it
# the model is a relation for Client Model
class JWEKey(JWKKey):
    @classmethod
    def keyset(cls):
        raise JWEPrivateError()

    def __custom_key_generator(self, key):
        key["use"] = "enc"
        return super().__custom_key_generator(key)
