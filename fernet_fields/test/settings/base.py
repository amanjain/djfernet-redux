INSTALLED_APPS = [
    'fernet_fields.test',
]

SECRET_KEY = 'secret'

SILENCED_SYSTEM_CHECKS = ['1_7.W001']

USE_TZ = False

# Dedicated equality-index key; independent of the encryption keyring.
FERNET_EMAIL_HASH_KEY = 'test-only-email-index-key-at-least-32-bytes'
