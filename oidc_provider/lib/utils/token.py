from datetime import timedelta
import time
import uuid
import json

from Cryptodome.PublicKey.RSA import importKey
from django.utils import dateformat, timezone
from jwkest.jwk import RSAKey as jwk_RSAKey
from jwkest.jwk import SYMKey
from jwkest.jws import JWS
from jwkest.jwt import JWT

from oidc_provider.lib.utils.common import (
    get_issuer,
    run_processing_hook,
    decode_base64,
    get_client_model
)
from oidc_provider.lib.claims import StandardScopeClaims
from oidc_provider.lib.errors import (
    ClientIdError, 
    BearerTokenError
)
from oidc_provider.models import (
    Code,
    RSAKey,
    Token,
    Client,
)
from oidc_provider import settings


def create_id_token(token, user, aud, nonce='', at_hash='', request=None, scope=None):
    """
    Creates the id_token dictionary.
    See: http://openid.net/specs/openid-connect-core-1_0.html#IDToken
    Return a dic.
    """
    if scope is None:
        scope = []
    sub = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user)

    expires_in = settings.get('OIDC_IDTOKEN_EXPIRE')

    # Convert datetimes into timestamps.
    now = int(time.time())
    iat_time = now
    exp_time = int(now + expires_in)
    user_auth_time = user.last_login or user.date_joined
    auth_time = int(dateformat.format(user_auth_time, 'U'))

    dic = {
        'iss': get_issuer(request=request),
        'sub': sub,
        'aud': str(aud),
        'exp': exp_time,
        'iat': iat_time,
        'auth_time': auth_time,
    }

    if nonce:
        dic['nonce'] = str(nonce)

    if at_hash:
        dic['at_hash'] = at_hash

    # Inlude (or not) user standard claims in the id_token.
    if settings.get('OIDC_IDTOKEN_INCLUDE_CLAIMS'):
        if settings.get('OIDC_EXTRA_SCOPE_CLAIMS'):
            custom_claims = settings.get('OIDC_EXTRA_SCOPE_CLAIMS', import_str=True)(token)
            claims = custom_claims.create_response_dic()
        else:
            claims = StandardScopeClaims(token).create_response_dic()
        dic.update(claims)

    dic = run_processing_hook(
        dic, 'OIDC_IDTOKEN_PROCESSING_HOOK',
        user=user, token=token, request=request)

    return dic


def encode_jwt(payload, client):
    """
    Represent payload as a JSON Web Token (JWT).
    Return a hash.
    """
    keys = get_client_alg_keys(client)
    _jws = JWS(payload, alg=client.jwt_alg)
    return _jws.sign_compact(keys)


def decode_jwt(jwt, client):
    """
    Decode a JSON Web Token (JWT). If the signature doesn't match, raise BadSignature.
    Return a dict.
    """
    keys = get_client_alg_keys(client)
    return JWS().verify_compact(jwt, keys=keys)


def client_id_from_id_token(id_token):
    """
    Extracts the client id from a JSON Web Token (JWT).
    Returns a string or None.
    """
    payload = JWT().unpack(id_token).payload()
    aud = payload.get('aud', None)
    if aud is None:
        return None
    if isinstance(aud, list):
        return aud[0]
    return aud


def create_token(user, client, scope, id_token_dic=None, request=None):
    """
    Create and populate a Token object.
    Return a Token object.
    """
    token = Token()
    token.user = user
    token.client = client
    token.access_token = uuid.uuid4().hex

    if id_token_dic is not None:
        token.id_token = id_token_dic

    token.refresh_token = uuid.uuid4().hex
    token.expires_at = timezone.now() + timedelta(seconds=settings.get('OIDC_TOKEN_EXPIRE'))
    token.scope = scope

    return token


def access_token_format(token, client, request, user=None):
    if settings.get('OIDC_ACCESS_TOKEN_ENCODE') is None:
        return token.access_token

    return settings.get('OIDC_ACCESS_TOKEN_ENCODE', import_str=True)(
        user=user,
        client=client,
        token=token,
        request=request)


def encode_access_token_jwt(user, client, token, request):
    """
    Generate a JWT Access Token Response.
    Return JWT String object (return a hash).
    """
    payload = {
        'iss': get_issuer(request=request),
        'client_id': str(client.client_id),
        'exp': int(token.expires_at.timestamp()),
        'iat': int(timezone.now().timestamp()),
        'scope': token.scope,
        'jti': token.access_token,
    }

    if user is not None:
        payload['sub'] = settings.get('OIDC_IDTOKEN_SUB_GENERATOR', import_str=True)(user=user)

    if settings.get('OIDC_TOKEN_JWT_AUD') is not None:
        payload['aud'] = settings.get('OIDC_TOKEN_JWT_AUD', import_str=True)(client=client)

    if settings.get('OIDC_TOKEN_JWT_EXTRA_INFO'):
        extra_info = settings.get('OIDC_TOKEN_JWT_EXTRA_INFO', import_str=True)(token)
        payload.update(extra_info)

    return encode_jwt(payload, client)


def wrapper_decode_jwt(access_token_jwt):
    try:
        not_verified_payload = decode_base64(access_token_jwt.split('.')[1])
    except Exception:
        raise BearerTokenError('invalid_token')

    try:
        payload_json = json.loads(not_verified_payload)
        client_class = get_client_model()
        client = client_class.objects.get(client_id=payload_json['client_id'])
    except Client.DoesNotExist:
        raise ClientIdError()

    jwt_payload = decode_jwt(jwt=access_token_jwt, client=client)

    return jwt_payload


def decode_access_token_jwt(access_token_jwt):
    jwt_payload = wrapper_decode_jwt(access_token_jwt=access_token_jwt)
    return jwt_payload['jti']


def get_plain_access_token(access_token):
    if settings.get('OIDC_ACCESS_TOKEN_DECODE') is None:
        return access_token

    return settings.get('OIDC_ACCESS_TOKEN_DECODE', import_str=True)(
        access_token_jwt=access_token)


def create_code(user, client, scope, nonce, is_authentication,
                code_challenge=None, code_challenge_method=None):

    """
    Create and populate a Code object.
    Return a Code object.
    """

    code = Code()
    code.user = user
    code.client = client

    code.code = uuid.uuid4().hex

    if code_challenge and code_challenge_method:
        code.code_challenge = code_challenge
        code.code_challenge_method = code_challenge_method

    code.expires_at = timezone.now() + timedelta(
        seconds=settings.get('OIDC_CODE_EXPIRE'))
    code.scope = scope
    code.nonce = nonce
    code.is_authentication = is_authentication

    return code


def get_client_alg_keys(client):
    """
    Takes a client and returns the set of keys associated with it.
    Returns a list of keys.
    """
    if client.jwt_alg == 'RS256':
        keys = []
        for rsakey in RSAKey.objects.all():
            keys.append(jwk_RSAKey(key=importKey(rsakey.key), kid=rsakey.kid))
        if not keys:
            raise Exception('You must add at least one RSA Key.')
    elif client.jwt_alg == 'HS256':
        keys = [SYMKey(key=client.client_secret, alg=client.jwt_alg)]
    else:
        raise Exception('Unsupported key algorithm.')

    return keys
