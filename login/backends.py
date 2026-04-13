from django.contrib.auth.backends import ModelBackend
from django.db import models
from django.db.models import Q

import ldap

from base.settings_hybit import LDAP_BASE_DN, LDAP_SERVER
from .models import myuser


class ModelBackendWithEmail(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        """Change authenticate of ModelBackend

        Args:
            request: not used
            username(str): username or email from login form
            password(str): user password from login form
        """
        try:
            # find user object based on name OR email
            user = myuser.objects.get(Q(name=username) | Q(email=username))
        except models.ObjectDoesNotExist:
            return None

        if user.check_password(password):
            return user
        else:
            return None


class ModelBackendWithLDAP(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        """Change authenticate of ModelBackend

        Args:
            request: not used
            username(str): username or email from login form
            password(str): user password from login form
        """
        if password is not None and len(password) > 0:
            try:
                ldap_conn = ldap.initialize(LDAP_SERVER) # 389
            except ldap.SERVER_DOWN:
                print("Login: ldap.SERVER_DOWN: LDAP connection failed")
                return None
                # login failed

            user_data = None
            try:
                base_dn = LDAP_BASE_DN

                user_search_result = ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, "(uid=%s)" % username)
                if len(user_search_result) == 1:
                    user_dn = user_search_result[0][0]

                    ldap_conn.simple_bind_s(user_dn, password)

                    ldap_filter = "uid=%s" % username

                    data = ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, ldap_filter)
                    if len(data) == 1:
                        user_data = data[0][1]

                        uid = user_data['uid'][0].decode('utf-8')
                        email = user_data['mail'][0].decode('utf-8')
                        name = user_data['cn'][0].decode('utf-8')

                        ldap_conn.unbind_s()

            except ldap.INVALID_CREDENTIALS:
                print("Login: ldap.INVALID_CREDENTIALS: LDAP login failed for %s" % username)
                return None

            if user_data is not None:
                # let's check if we have a user
                try:
                    # find user object based on name OR email
                    return myuser.objects.get(Q(name=uid))
                except models.ObjectDoesNotExist:
                    # create user
                    u = myuser.objects.create_devuser(uid, email)
                    u.fullname = name
                    u.save()

                    return u

            print("Login: No fitting user data found, total records: %d" % len(data))

            return None
