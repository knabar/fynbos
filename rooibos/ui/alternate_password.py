
from django.contrib.auth.models import User, check_password, get_hexdigest
from rooibos.userprofile.views import load_settings, store_settings

import logging
logger = logging.getLogger(__name__)


def check_alternate_password(username, password):
    if not password:
        return None
    try:
        user = User.objects.get(username=username)
        setting = load_settings(user, filter='alternate_password')
        alternate_password = setting['alternate_password'][0]
        if alternate_password == "!":
            logger.debug('Alternate password disabled')
            user = None
        elif not check_password(password, alternate_password):
            logger.debug('Alternate password check failed')
            user = None
    except User.DoesNotExist:
        logger.debug('User not found')
        user = None
    except (KeyError, IndexError):
        logger.debug('Alternate password not found')
        user = None
    if user:
        # Fake regular authentication backend
        user.backend = 'django.contrib.auth.backends.ModelBackend'
    return user

def _get_encoded_password(raw_password):
    import random
    algo = 'sha1'
    salt = get_hexdigest(algo, str(random.random()), str(random.random()))[:5]
    hsh = get_hexdigest(algo, salt, raw_password)
    return '%s$%s$%s' % (algo, salt, hsh)

def set_alternate_password(user, password):
    logger.debug('Setting alternate password for "%s"' % user.username)
    encoded_password = _get_encoded_password(password) if password else '!'
    logger.debug('Setting password to "%s"' % encoded_password[:5])
    return store_settings(user, 'alternate_password', encoded_password)
