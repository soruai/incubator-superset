import logging
import os
import pickle
import redis

from flask import g, redirect, request
from flask_appbuilder.baseviews import expose
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask_appbuilder.security.views import AuthRemoteUserView
from flask_login import login_user, logout_user
from sqlalchemy import create_engine, text
from sqlalchemy.orm import joinedload, sessionmaker
from superset.security import SupersetSecurityManager

# Superset configuration values.
MAPBOX_API_KEY = os.getenv('MAPBOX_API_KEY', '')
REDIS_URL = os.getenv('REDIS_URL', 'redis://redis:6379/0')
CACHE_CONFIG = {
    'CACHE_TYPE': 'redis',
    'CACHE_DEFAULT_TIMEOUT': 300,
    'CACHE_KEY_PREFIX': 'superset_',
    'CACHE_REDIS_URL': REDIS_URL
}
SQLALCHEMY_DATABASE_URI = os.getenv('SUPERSET_METADATA_DATABASE_URL')
SQLALCHEMY_TRACK_MODIFICATIONS = True
SECRET_KEY = os.getenv('SECRET_KEY')
# TODO(ertan): Tighten these security constraints.
WTF_CSRF_ENABLED = False
ENABLE_CORS = True
DEBUG = os.getenv('DEBUG')
CORS_OPTIONS = {
    'supports_credentials': True
}
ENABLE_ACCESS_REQUEST = True

# SORU session related constants.
# WARNING: Keep these in sync with SORU Django's common.py
DJANGO_CACHE_VERSION = 1
# As defined here: https://git.io/vppz6
# Note that cached_db returns decoded results, db returns byte64 encoded ones.
DJANGO_SESSION_ENGINE = 'django.contrib.sessions.cached_db'
DJANGO_REDIS_KEY_PREFIX = 'soru_django_redis'
# Misc SORU specific constants.
ADMIN_USERNAME = 'admin'
SCREENSHOTTER_COOKIE_NAME = 'screenshottersession'
SORU_COOKIE_NAME = 'sorusessionid'
DJANGO_SESSION_AUTH_USER_ID = '_auth_user_id'
DEFAULT_USER_ROLE = 'Gamma'
SORU_DATABASE_URL = os.getenv('SORU_DATABASE_URL')
# Used inside Soru's custom superset instance.
SORU_EXTERNAL_HOST = os.getenv('SORU_EXTERNAL_HOST')
SORU_API_HOST = os.getenv('SORU_API_HOST')
# TODO(ertan): Make allowed origin work for both http and https. Right now it
# only works with SORU_EXTERNAL_HOST.
HTTP_HEADERS = {
    'X-Frame-Options': 'ALLOW-FROM https://chart.soru.ai',
    'Access-Control-Allow-Origin': SORU_EXTERNAL_HOST,
    'Access-Control-Allow-Headers': 'Access-Control-Allow-Origin'
}

# Variables to be used in the SecurityManager, et al.
logger = logging.getLogger(__name__)
_engine = create_engine(SQLALCHEMY_DATABASE_URI,
                        convert_unicode=True, pool_size=10, max_overflow=20)
Session = sessionmaker(bind=_engine)
_soru_engine = create_engine(SORU_DATABASE_URL,
                             convert_unicode=True, pool_size=10,
                             max_overflow=20)
SoruSession = sessionmaker(bind=_soru_engine)


def construct_soru_key(key):
    if not key:
        return
    return ':'.join([DJANGO_REDIS_KEY_PREFIX, str(DJANGO_CACHE_VERSION), key])


def get_userid_from_session():
    session_id = request.cookies.get(SORU_COOKIE_NAME)
    if not session_id:
        return
    key = DJANGO_SESSION_ENGINE + session_id
    redis_conn = redis.StrictRedis.from_url(REDIS_URL)
    session_key = construct_soru_key(key)
    pickled_session = redis_conn.get(session_key)
    if not pickled_session:
        return
    session_dict = pickle.loads(pickled_session)
    return session_dict.get(DJANGO_SESSION_AUTH_USER_ID)


def is_request_from_trusted_source():
    # TODO(ertan): Use cookies once setCookies start working on puppeteer.
    session_id = (request.cookies.get(SCREENSHOTTER_COOKIE_NAME) or
                  construct_soru_key(request.cookies.get(SORU_COOKIE_NAME)))
    if not session_id:
        return False
    redis_conn = redis.StrictRedis.from_url(REDIS_URL)
    # We only use each session once
    return redis_conn.get(session_id)


def login_admin(user_model):
    session = Session()
    # TODO(ertan): Do this properly, filter_by.first might cause issues.
    try:
        user = session.query(user_model).options(
            joinedload('roles').subqueryload('permissions')).filter_by(
            username=ADMIN_USERNAME).first()
        login_user(user)
        request.environ['REMOTE_USER'] = ADMIN_USERNAME
        session.commit()
    except Exception:
        session.rollback()


def get_superset_user(user_id, user_model):
    soru_session = SoruSession()
    try:
        result = soru_session.execute(
            text('SELECT username FROM users_user WHERE id = :id'),
            {'id': str(user_id)}
        ).first()
        username = result[0]
        soru_session.commit()
    except Exception:
        soru_session.rollback()
        raise

    session = Session()
    try:
        user = session.query(user_model).options(
            joinedload('roles').subqueryload('permissions')).filter_by(
            username=username).first()
        session.commit()
    except Exception:
        session.rollback()
        raise
    return user, username


class SoruAuthRemoteUserView(AuthRemoteUserView):
    def add_role_if_missing(self, sm, user_id, role_name):
        found_role = sm.find_role(role_name)
        session = sm.get_session
        try:
            user = session.query(sm.user_model).options(
                joinedload('roles').subqueryload('permissions')).get(
                user_id)
            if found_role and found_role not in user.roles:
                user.roles += [found_role]
            session.commit()
        except Exception:
            session.rollback()

    @expose('/login/')
    def login(self):
        user_id = get_userid_from_session()
        if not user_id:
            return 'Session has ended.'
        if g and g.user is not None:
            if g.user.is_authenticated():
                return redirect(self.get_redirect())

        sm = self.appbuilder.sm
        user, username = get_superset_user(user_id, sm.user_model)
        if user and not user.is_active():
            return (
                'Your account is not activated, '
                'ask an admin to check the \'Is Active?\' box in your '
                'user profile')
        role = sm.find_role(DEFAULT_USER_ROLE)
        if user is None and username:
            user = sm.add_user(
                username=username,
                first_name=username,
                last_name='',
                email='{}@soru.ai'.format(username),
                role=role)
            user = sm.auth_user_remote_user(username)

        login_user(user)
        return redirect(self.get_redirect())


class CustomSecurityManager(SupersetSecurityManager):
    authremoteuserview = SoruAuthRemoteUserView

    @staticmethod
    def before_request():
        super(CustomSecurityManager,
              CustomSecurityManager).before_request()
        if is_request_from_trusted_source():
            login_admin(CustomSecurityManager.user_model)
            return
        user_id = get_userid_from_session()
        if not user_id:
            logout_user()
            return
        user, username = get_superset_user(user_id,
                                           CustomSecurityManager.user_model)
        if not user:
            logout_user()
            return
        # TODO(ertan): Enable CSRF protection based on the caller and some
        # shared secret token.
        if g.user.is_anonymous():
            login_user(user)
            return
        if username != g.user.username:
            logout_user()
        request.environ['REMOTE_USER'] = username


# Security manager related constants.
AUTH_TYPE = AUTH_REMOTE_USER
AUTH_USER_REGISTRATION_ROLE = DEFAULT_USER_ROLE
CUSTOM_SECURITY_MANAGER = CustomSecurityManager
