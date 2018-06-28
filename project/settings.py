"""
Django settings for project project.

Generated by 'django-admin startproject' using Django 1.10.3.

For more information on this file, see
https://docs.djangoproject.com/en/1.10/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.10/ref/settings/
"""

import os
import dj_database_url


# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))

# Website root url
ROOT_URL = os.environ.get('ROOT_URL', 'localhost:8000')


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.10/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = str(os.environ.get('DJANGO_SECRET'))

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = eval(str(os.environ.get('DEBUG', 'False')).capitalize())

# manage.py test mode that disables fb connection stuff
TEST_MODE = eval(str(os.environ.get('TEST_MODE', 'False')).capitalize())

ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'custom_auth',
    'main',
    'spotteds',
    'moderation',
    'api',
    'chatbot',

    'captcha',
    'maintenance_mode',
]

if DEBUG:
    INSTALLED_APPS.append('sslserver')


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'maintenance_mode.middleware.MaintenanceModeMiddleware',
]

ROOT_URLCONF = 'project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'main.context_processors.enable_mod_shift',
                'main.context_processors.enable_imgur_upload',
                'main.context_processors.enable_recaptcha',
                'main.context_processors.enable_ad_tag',
                'main.context_processors.ad_slot',
                'main.context_processors.analytics_id',
                'main.context_processors.facebook_app_id',
                'main.context_processors.enable_coinhive'
            ],
        },
    },
]

WSGI_APPLICATION = 'project.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.10/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}


# Password validation
# https://docs.djangoproject.com/en/1.10/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/1.10/topics/i18n/

LANGUAGE_CODE = 'pt-br'

TIME_ZONE = 'America/Sao_Paulo'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.10/howto/static-files/

STATIC_ROOT = os.path.join(PROJECT_ROOT, 'staticfiles')
STATIC_URL = '/static/'


# Simplified static file serving.
# https://warehouse.python.org/project/whitenoise/
STATICFILES_STORAGE = 'whitenoise.django.GzipManifestStaticFilesStorage'

FILE_UPLOAD_HANDLERS = ['django.core.files.uploadhandler.TemporaryFileUploadHandler']

# Extra places for collectstatic to find static files.
STATICFILES_DIRS = (
    os.path.join(PROJECT_ROOT, 'static'),
)


# Update database configuration with $DATABASE_URL.
db_from_env = dj_database_url.config(conn_max_age=500)
DATABASES['default'].update(db_from_env)

# Maintenance Mode
MAINTENANCE_MODE = eval(os.environ.get('MAINTENANCE_MODE', 'None'))
MAINTENANCE_MODE_TEMPLATE = 'main/503.html'
MAINTENANCE_MODE_IGNORE_ADMIN_SITE = True
MAINTENANCE_MODE_IGNORE_SUPERUSER = True

# Honor the 'X-Forwarded-Proto' header for request.is_secure()
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

LOGIN_URL = '/auth/facebook/login/'
LOGIN_REDIRECT_URL = '/dashboard/'

DEFAULT_CONTACT_EMAIL = str(os.environ.get('EMAIL_ACCOUNT'))
DEFAULT_FROM_EMAIL = str(os.environ.get('EMAIL_ACCOUNT'))
EMAIL_HOST_USER = str(os.environ.get('EMAIL_ACCOUNT'))
EMAIL_HOST_PASSWORD = str(os.environ.get('EMAIL_PASSWORD'))
EMAIL_USE_TLS = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
SERVER_EMAIL = str(os.environ.get('EMAIL_ACCOUNT'))

ADMINS = eval(os.environ.get('ADMIN_ACCOUNT', "[('Admin', ), ]"))


# Moderation Hours
ENABLE_MOD_SHIFT = False

# Facebook Stuff
FACEBOOK_KEY = os.environ.get('FACEBOOK_KEY')
FACEBOOK_SECRET = os.environ.get('FACEBOOK_SECRET')
FACEBOOK_PAGE_TOKEN = os.environ.get('FACEBOOK_PAGE_TOKEN')
FACEBOOK_USE_CHATBOT = eval(os.environ.get('FACEBOOK_USE_CHATBOT', 'false').capitalize())
FACEBOOK_VERIFY_CHATBOT = os.environ.get('FACEBOOK_VERIFY_CHATBOT', 'abc')
FACEBOOK_PERMISSIONS = []

# Page Stuff
INITIAL_COUNT = int(os.environ.get('INITIAL_COUNT', '0'))

# Google Captcha stuff
RECAPTCHA_PUBLIC_KEY = os.environ.get('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = os.environ.get('RECAPTCHA_PRIVATE_KEY')
NOCAPTCHA = True

# Imgur stuff
IMGUR_CLIENT = os.environ.get('IMGUR_CLIENT')
IMGUR_SECRET = os.environ.get('IMGUR_SECRET')

# Web Of Trust
WOT_SECRET = os.environ.get('WOT_SECRET')

# Google Safe Browsing
GSB_SECRET = os.environ.get('GSB_SECRET')

# Spotted API
SPOTTED_API_URL = os.environ.get('SPOTTED_API_URL', "http://spottedapi.herokuapp.com")
SPOTTED_API_SECRET = os.environ.get('SPOTTED_API_SECRET')

# Celery stuff
CELERY_BROKER_URL = str(os.environ.get('REDIS_URL'))

# Google Analytics
GOOGLE_ANALYTICS_ID = os.environ.get('GOOGLE_ANALYTICS_ID', False)

# Adsense

# Please do not alter the dev ads, as I provide you with free code and API support for you to make money. Allow me a share out of it :)
DEV_AD = os.environ.get("DEV_AD", 'ca-pub-7213431984816764')
SPOTTED_AD = os.environ.get('SPOTTED_AD', False)
ADS_ACTIVE = eval(os.environ.get('ADS_ACTIVE', 'False'))
AD_TEST = eval(os.environ.get('AD_TEST', 'False'))
AD_SLOTS = eval(os.environ.get('AD_SLOTS', '[]'))
if not len(AD_SLOTS) and AD_TEST:
    AD_SLOTS = ["slot 1", "slot 2", "slot 3"]
ADS_APPROVED = True if AD_SLOTS else False


# Please do not alter the dev coinhive token, as I provide you with free code and API support for you to make money. Allow me a share out of it :)
DEV_COINHIVE = "VRt0VLErmTT5sXpt2tEg72qlELmUIJZu"
SPOTTED_COINHIVE = eval(os.environ.get('SPOTTED_COINHIVE', 'False'))
ENABLE_COINHIVE = eval(os.environ.get('ENABLE_COINHIVE', 'False'))
