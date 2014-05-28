from django.contrib.auth.models import User
from django.conf import settings
import ldap
from baseauth import BaseAuthenticationBackend
import logging


def _ldap_const(name):
    try:
        return getattr(ldap, name)
    except (TypeError, AttributeError):
        return name


class LdapAuthenticationBackend(BaseAuthenticationBackend):
    def authenticate(self, username=None, password=None):
        for ldap_auth in settings.LDAP_AUTH:
            try:
                for option, value in ldap_auth['options'].iteritems():
                    if option.startswith('OPT_X_TLS_'):
                        logging.info('LDAP: Setting ldap option %s to %s', option, value)
                        ldap.set_option(_ldap_const(option), value)
                username = username.strip()
                logging.info('LDAP: Initializing connection to %s', ldap_auth['uri'])
                l = ldap.initialize(ldap_auth['uri'])
                logging.info('LDAP: Setting protocol version to %s', ldap_auth['version'])
                l.protocol_version = _ldap_const(ldap_auth['version'])
                for option, value in ldap_auth['options'].iteritems():
                    if not option.startswith('OPT_X_TLS_'):
                        logging.info('LDAP: Setting connection option %s to %s', option, value)
                        l.set_option(_ldap_const(option), value)

                dn = '%s=%s,%s' % (ldap_auth['cn'],
                                   username, ldap_auth['base'])

                if ldap_auth.get('bind_user'):
                    logging.info('LDAP: Binding with bind user')
                    l.simple_bind_s(ldap_auth['bind_user'],
                                    ldap_auth.get('bind_password'))
                    if ldap_auth.get('bind_user_get_attrs'):
                        attrlist = ldap_auth['attributes']
                    else:
                        attrlist = ()
                    dn_field = ldap_auth.get('dn')
                    if dn_field:
                        attrlist += (dn_field,)
                    logging.info('LDAP: Searching for user and fetching attributes %s' % attrlist)
                    result = l.search_s(
                        ldap_auth['base'],
                        _ldap_const(ldap_auth['scope']),
                        '%s=%s' % (ldap_auth['cn'], username),
                        attrlist=attrlist)
                    if (len(result) != 1):
                        logging.info('LDAP: Did not find exactly one user')
                        continue
                    if dn_field:
                        dn = result[0][1].get(dn_field)
                        if type(dn) in (tuple, list):
                            dn = dn[0]

                logging.info('LDAP: Binding with dn=%s' % dn)
                l.simple_bind_s(dn, password)
                attrlist = []
                if not ldap_auth.get('bind_user_get_attrs'):
                    attrlist = ldap_auth['attributes']
                logging.info('LDAP: Searching')
                result = l.search_s(ldap_auth['base'],
                                    _ldap_const(ldap_auth['scope']),
                                    '%s=%s' % (ldap_auth['cn'], username),
                                    attrlist=attrlist)
                if (len(result) != 1):
                    continue
                logging.info('LDAP: Processing attributes')
                attributes = result[0][1]
                for attr in ldap_auth['attributes']:
                    if attr in attributes:
                        if not type(attributes[attr]) in (tuple, list):
                            attributes[attr] = (attributes[attr],)
                    else:
                        attributes[attr] = []
                try:
                    user = User.objects.get(username=username)
                except User.DoesNotExist:
                    user = self._create_user(
                        username,
                        None,
                        ' '.join(attributes[ldap_auth['firstname']]),
                        ' '.join(attributes[ldap_auth['lastname']]),
                        attributes[ldap_auth['email']][0])
                if not self._post_login_check(user, attributes):
                    continue
                return user
            except ldap.LDAPError, error_message:
                logging.debug('LDAP error: %s' % error_message)
            finally:
                if l:
                    l.unbind_s()
        return None
