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
    View decorator. The client accesses protected resources by presenting the
    access token to the resource server.
    https://tools.ietf.org/html/rfc6749#section-7
    """
    if scopes is None:
        scopes = []

    def wrapper_method(view_method):
        
        args_name = inspect.getfullargspec(view_method)[0]
        if not 'request' in args_name:
            raise RuntimeError(
                    "This decorator can only work with django (or drf) view methods " \
                    "with the \"request\" parameter as first or second argument. " \
                    "Examples: def action  (request, *args, **kwargs) or def action(self, request, *args, **kwargs)")
        
        if not hasattr(view_method, 'kwargs'):
            view_method.kwargs = {}
        if not 'required_scopes' in view_method.kwargs:
            view_method.kwargs['required_scopes'] = set()
        view_method.kwargs['required_scopes'].update(scopes)
        
        @wraps(view_method)
        def view_wrapper(*args, **kwargs):
            
            request = args[args_name.index('request')]

            set_token_in_request(request)

            try:
                if request.token.has_expired():
                    logger.debug('[UserInfo] Token has expired: %s', request.access_token)
                    raise BearerTokenError('invalid_token')

                if not view_method.kwargs['required_scopes'].issubset(set(request.token.scope)):
                    logger.debug('[UserInfo] Missing openid scope.')
                    raise BearerTokenError('insufficient_scope')
            except BearerTokenError as error:
                response = HttpResponse(status=error.status)
                response['WWW-Authenticate'] = 'error="{0}", error_description="{1}"'.format(
                    error.code, error.description)
                return response

            return view_method(*args, **kwargs)

        return view_wrapper

    def wrapper(view):
        if inspect.isclass(view):
            # level class attribute
            for view_method in get_view_methods(view):
                setattr(view, view_method[0], wrapper_method(view_method[1]))
            # persist required scopes on class to provide annotation to derived view methods.
            view.required_scopes = set(scopes)
        elif callable(view) and hasattr(view, 'cls'):
            # 'cls' attr signals that as_view() was called
            for view_method in get_view_methods(view.cls):
                setattr(view, view_method[0], wrapper_method(view_method[1]))
        elif callable(view):
            wrapper_method(view)
        return view

    return wrapper
