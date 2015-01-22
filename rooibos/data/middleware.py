from django.core.exceptions import MiddlewareNotUsed
import logging
from models import get_system_field

class DataOnStart:

    def __init__(self):

        # initialize system field, so later it does not get created multiple
        # times in a race condition

        get_system_field()


        from rooibos.access import add_restriction_precedence

        def personalimage_precedence(a, b):
            if a == 'no' or b == 'no':
                return 'no'
            elif a == 'yes' or b == 'yes':
                return 'yes'
            else:
                return None
        add_restriction_precedence('personalimages', personalimage_precedence)


        # Only need to run once
        raise MiddlewareNotUsed
