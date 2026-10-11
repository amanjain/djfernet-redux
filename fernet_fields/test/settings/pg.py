from .base import *  # noqa


import os

# Defaults match the GitHub Actions config; override for local runs.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql_psycopg2',
        'NAME': 'djftest',
        'USER': os.environ.get('DJFERNET_TEST_PG_USER', 'postgres'),
        'PASSWORD': os.environ.get('DJFERNET_TEST_PG_PASSWORD', 'postgres'),
        'HOST': os.environ.get('DJFERNET_TEST_PG_HOST', 'localhost'),
        'PORT': os.environ.get('DJFERNET_TEST_PG_PORT', '5432'),
        'TEST': {
            'NAME': 'djftest',
        },
    },
}
