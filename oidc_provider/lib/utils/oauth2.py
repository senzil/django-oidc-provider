from base64 import b64decode
from functools import wraps
import inspect
import logging
import re

from django.http import HttpResponse

from jwkest import BadSignature

from oidc_provider.lib.errors import (
    BearerTokenError,
    ClientIdError
)
from oidc_provider.lib.utils.token import (
    get_plain_access_token,
    wrapper_decode_jwt,
)
from oidc_provider.models import Token


logger = logging.getLogger(__name__)

def extract_authorization_token(request):
    """
    Get the access token using Authorization Request Header Field method.
    Or try getting via GET.
    See: http://tools.ietf.org/html/rfc6750#section-2.1

    Return a string.
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')

    if re.compile(r'^[Bb]earer\s{1}.+$').match(auth_header):
        access_token = auth_header.split()[1]
    else:
        access_token = request.GET.get('access_token', '')
    
    return access_token


def extract_access_token(request):
    """
    Get the access token using Authorization Request Header Field method.
    Or try getting via GET.
    See: http://tools.ietf.org/html/rfc6750#section-2.1

    Return a string.
    """
    
    access_token = extract_authorization_token(request)

    try:
        access_token = get_plain_access_token(access_token=access_token)
    except BadSignature:
        raise BearerTokenError('invalid_token')
    except ClientIdError:
        raise BearerTokenError('invalid_token')

    return access_token


def extract_payload(request):
    """
    Get the JWT Payload using Authorization Request Header Field method.
    Or try getting via GET.
    See: http://tools.ietf.org/html/rfc6750#section-2.1

    Return a json.
    """

    access_token = extract_authorization_token(request)

    try:
        payload = wrapper_decode_jwt(access_token_jwt=access_token)
    except BadSignature:
        raise BearerTokenError('invalid_token')
    except ClientIdError:
        raise BearerTokenError('invalid_token')

    return payload


def extract_client_auth(request):
    """
    Get client credentials using HTTP Basic Authentication method.
    Or try getting parameters via POST.
    See: http://tools.ietf.org/html/rfc6750#section-2.1

    Return a tuple `(client_id, client_secret)`.
    """
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')

    if re.compile(r'^Basic\s{1}.+$').match(auth_header):
        b64_user_pass = auth_header.split()[1]
        try:
            user_pass = b64decode(b64_user_pass).decode('utf-8').split(':')
            client_id, client_secret = tuple(user_pass)
        except Exception:
            client_id = client_secret = ''
    else:
        client_id = request.POST.get('client_id', '')
        client_secret = request.POST.get('client_secret', '')

    return (client_id, client_secret)

def set_token_in_request(request):
    request.access_token = getattr(request, 'access_token', extract_access_token(request))

    try:
        request.token = getattr(request, 'token', Token.objects.get(access_token=request.access_token))
    except Token.DoesNotExist:
        logger.debug('[UserInfo] Token does not exist: %s', request.access_token)
        raise BearerTokenError('invalid_token')

def get_view_methods(view):
    #for drf compatibility
    drf_viewset_mappings = [
        'list', 
        'retrieve',
        'create',
        'update',
        'partial_update',
        'destroy'
        ]
    return [ item for item in inspect.getmembers(view)
                if (item[0] in view.http_method_names
                    or hasattr(item[1], 'mapping')
                    or item[0] in drf_viewset_mappings)
        ]


def protected_resource_view(scopes=None):
    """
    Decorador que protege recursos asegurando que se presenten los scopes requeridos.
    Compatible con funciones, CBVs y ViewSets.
    """
    if scopes is None:
        scopes = []

    def wrapper_method(view_func):
        @wraps(view_func)
        def wrapper(self_or_request, *args, **kwargs):
            # Determinar si es una CBV/ViewSet o una función
            if hasattr(self_or_request, "method"):
                # Caso de FBV, el primer argumento es `request`
                request = self_or_request
            else:
                # Caso de CBV o ViewSet, `self` es el primer argumento y `request` el segundo
                self = self_or_request
                request = args[0]

            # Agregar scopes requeridos
            if not hasattr(view_func, 'kwargs'):
                view_func.kwargs = {}
            if 'required_scopes' not in view_func.kwargs:
                view_func.kwargs['required_scopes'] = set()
            view_func.kwargs['required_scopes'].update(scopes)

            # Extraer y validar el token
            set_token_in_request(request)
            try:                
                if request.token.has_expired():
                    logger.debug('[UserInfo] Token has expired: %s', request.access_token)
                    raise BearerTokenError('invalid_token')

                if not view_func.kwargs['required_scopes'].issubset(set(request.token.scope)):
                    logger.debug('[UserInfo] Missing openid scope.')

            except BearerTokenError as error:
                response = HttpResponse(status=error.status)
                response['WWW-Authenticate'] = 'error="{0}", error_description="{1}"'.format(
                    error.code, error.description)
                return response

            # Ejecutar la vista original
            if hasattr(self_or_request, "method"):
                return view_func(request, *args, **kwargs)
            else:
                return view_func(self, request, *args, **kwargs)

        return wrapper

    def wrapper(view):
        # Caso CBV o ViewSet: Decorar métodos estándar (como `dispatch`)
        if inspect.isclass(view):
            for method_name in ["dispatch", "get", "post", "put", "delete"]:
                if hasattr(view, method_name):
                    original_method = getattr(view, method_name)
                    decorated_method = wrapper_method(original_method)
                    setattr(view, method_name, decorated_method)
            return view

        # Caso función o método
        return wrapper_method(view)

    return wrapper