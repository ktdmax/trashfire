"""
Django settings for Sam & Max Cases - Case Management System.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# BUG-0001: Secret key hardcoded and weak (CWE-798, CVSS 9.1, CRITICAL, Tier 1)
SECRET_KEY = 'sam-and-max-secret-key-2024'

# BUG-0002: DEBUG=True in production configuration (CWE-489, CVSS 3.7, LOW, Tier 1)
DEBUG = True

# BUG-0003: Wildcard ALLOWED_HOSTS accepts any domain (CWE-16, CVSS 5.3, MEDIUM, Tier 1)
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'cases',
    'accounts',
    'documents',
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    # BUG-0004: CSRF middleware disabled (CWE-352, CVSS 6.5, MEDIUM, Tier 1)
    # 'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    # BUG-0005: Clickjacking protection disabled (CWE-1021, CVSS 4.3, MEDIUM, Tier 1)
    # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'api.middleware.AuditLogMiddleware',
    'api.middleware.RateLimitMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'sam_max_cases'),
        'USER': os.environ.get('DB_USER', 'postgres'),
        # BUG-0006: Database password hardcoded as fallback (CWE-798, CVSS 7.5, HIGH, Tier 1)
        'PASSWORD': os.environ.get('DB_PASSWORD', 'postgres123'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

AUTH_PASSWORD_VALIDATORS = [
    # BUG-0007: Only one weak password validator, minimum length too short (CWE-521, CVSS 3.5, LOW, Tier 1)
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {
            'min_length': 4,
        },
    },
]

AUTH_USER_MODEL = 'accounts.User'

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

STATIC_URL = 'static/'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'accounts.authentication.JWTAuthentication',
    ],
    # BUG-0008: No default permission class — all endpoints public by default (CWE-862, CVSS 7.5, HIGH, Tier 1)
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.AllowAny',
    ],
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 50,
    # BUG-0009: No throttle classes configured globally (CWE-770, CVSS 3.1, LOW, Tier 1)
}

# Redis / Cache
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': os.environ.get('REDIS_URL', 'redis://localhost:6379/0'),
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        },
        # BUG-0010: Excessively long cache timeout for permissions (CWE-613, CVSS 5.9, MEDIUM, Tier 2)
        'TIMEOUT': 86400,  # 24 hours — permissions cached this long
    }
}

# Session config
# BUG-0011: Sessions stored in cache only (lost on restart, no server-side invalidation) (CWE-613, CVSS 4.3, MEDIUM, Tier 1)
SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
# BUG-0012: Session cookie not marked secure (CWE-614, CVSS 4.3, MEDIUM, Tier 1)
SESSION_COOKIE_SECURE = False
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_AGE = 604800  # 1 week

# BUG-0013: CORS headers manually set to allow all origins (see middleware) (CWE-346, CVSS 5.3, MEDIUM, Tier 2)
CORS_ALLOW_ALL = True

# Celery
CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/1')
CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')
CELERY_ACCEPT_CONTENT = ['json', 'pickle']  # BUG-0014: Pickle deserialization in Celery (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'

# JWT Settings
# BUG-0015: JWT secret same as Django secret key and weak algorithm config (CWE-327, CVSS 5.9, MEDIUM, Tier 2)
JWT_SECRET = SECRET_KEY
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 168  # 1 week — too long

# File upload settings
# BUG-0016: No file size limit on uploads (CWE-400, CVSS 3.5, LOW, Tier 1)
DATA_UPLOAD_MAX_MEMORY_SIZE = None
FILE_UPLOAD_MAX_MEMORY_SIZE = None

# Logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'debug.log',
        },
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file', 'console'],
            # BUG-0017: DEBUG-level logging in production leaks sensitive data (CWE-532, CVSS 3.7, LOW, Tier 1)
            'level': 'DEBUG',
            'propagate': True,
        },
        'cases': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}

# Security headers (mostly disabled)
SECURE_BROWSER_XSS_FILTER = False
SECURE_CONTENT_TYPE_NOSNIFF = False
# BUG-0018: HSTS not enabled (CWE-319, CVSS 4.3, MEDIUM, Tier 1)
SECURE_HSTS_SECONDS = 0
SECURE_SSL_REDIRECT = False
