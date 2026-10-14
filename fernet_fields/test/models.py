from django.core.serializers.json import DjangoJSONEncoder
from django.db import models

import fernet_fields as fields
from fernet_fields.email import (
    SearchableEncryptedEmailField, SearchableEncryptedEmailManager,
    SearchableEncryptedEmailMixin,
)


class EncryptedText(models.Model):
    value = fields.EncryptedTextField()


class EncryptedChar(models.Model):
    value = fields.EncryptedCharField(max_length=25)


class EncryptedEmail(models.Model):
    value = fields.EncryptedEmailField()


class EncryptedInt(models.Model):
    value = fields.EncryptedIntegerField()


class EncryptedDate(models.Model):
    value = fields.EncryptedDateField()


class EncryptedDateTime(models.Model):
    value = fields.EncryptedDateTimeField()


class EncryptedNullable(models.Model):
    value = fields.EncryptedIntegerField(null=True)


class EncryptedBinary(models.Model):
    value = fields.EncryptedBinaryField()


class EncryptedBigIntegerField(fields.EncryptedField, models.BigIntegerField):
    """A custom field built the way the README describes."""


class EncryptedBigInt(models.Model):
    value = EncryptedBigIntegerField()


class EncryptedJSON(models.Model):
    value = fields.EncryptedJSONField(null=True)


class EncryptedJSONWithEncoder(models.Model):
    value = fields.EncryptedJSONField(encoder=DjangoJSONEncoder)


class EncryptedSearchableEmail(SearchableEncryptedEmailMixin, models.Model):
    value = SearchableEncryptedEmailField(hash_field='value_hash')
    value_hash = models.CharField(max_length=64, unique=True, editable=False, blank=True)
    optional = SearchableEncryptedEmailField(hash_field='optional_hash', null=True, blank=True)
    optional_hash = models.CharField(
        max_length=64, unique=True, editable=False, null=True, blank=True)
    objects = SearchableEncryptedEmailManager()
