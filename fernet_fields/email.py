"""Opt-in encrypted email lookup with a separate keyed equality index."""
import hashlib
import hmac

from django.conf import settings
from django.core import checks
from django.core.exceptions import FieldDoesNotExist, FieldError, ImproperlyConfigured
from django.db import models, transaction
from django.db.models.expressions import Col
from django.utils.encoding import force_bytes

from .fields import EncryptedEmailField, EncryptedField


def normalize_email(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError('Email values must be strings; expressions are not supported.')
    return value.strip().lower()


def email_digest(field, value):
    value = normalize_email(value)
    if value is None:
        return None
    key = getattr(settings, 'FERNET_EMAIL_HASH_KEY', None)
    if not isinstance(key, (str, bytes)) or len(force_bytes(key)) < 32:
        raise ImproperlyConfigured(
            'FERNET_EMAIL_HASH_KEY must be a dedicated key of at least 32 bytes.')
    # Bind the digest to this model/field to prevent cross-column correlation.
    domain = field.model._meta.label_lower + ':' + field.name + '\x00'
    return hmac.new(force_bytes(key), force_bytes(domain + value), hashlib.sha256).hexdigest()


class EmailEqualityLookup(models.Lookup):
    lookup_name = 'exact'

    def get_prep_lookup(self):
        return normalize_email(self.rhs)

    def as_sql(self, compiler, connection):
        if not isinstance(self.lhs, Col):
            raise FieldError('Encrypted email equality requires a model column.')
        field = self.lhs.output_field
        column = field.model._meta.get_field(field.hash_field).get_col(self.lhs.alias)
        lhs, params = compiler.compile(column)
        return '%s = %%s' % lhs, list(params) + [email_digest(field, self.rhs)]


class EmailInsensitiveEqualityLookup(EmailEqualityLookup):
    lookup_name = 'iexact'


class SearchableEncryptedEmailField(EncryptedEmailField):
    """Normalized encrypted email with equality delegated to a companion hash."""

    def __init__(self, *args, hash_field, **kwargs):
        self.hash_field = hash_field
        super().__init__(*args, **kwargs)

    def deconstruct(self):
        name, path, args, kwargs = super().deconstruct()
        kwargs['hash_field'] = self.hash_field
        return name, path, args, kwargs

    def get_prep_value(self, value):
        return normalize_email(super().get_prep_value(value))

    def check(self, **kwargs):
        errors = super().check(**kwargs)
        try:
            companion = self.model._meta.get_field(self.hash_field)
        except FieldDoesNotExist:
            companion = None
        valid = (
            companion is not None and isinstance(companion, models.CharField)
            and not isinstance(companion, EncryptedField)
            and companion.max_length == 64 and not companion.editable
            and companion.null == self.null and companion.concrete
            and not companion.primary_key
            and companion.model._meta.concrete_model == self.model._meta.concrete_model
        )
        if not valid:
            errors.append(checks.Error(
                'hash_field must name a non-editable CharField(max_length=64) with matching null.',
                obj=self, id='fernet_fields.E001'))
        if not issubclass(self.model, SearchableEncryptedEmailMixin):
            errors.append(checks.Error('Model must use SearchableEncryptedEmailMixin.',
                                       obj=self, id='fernet_fields.E002'))
        if not isinstance(self.model._default_manager.get_queryset(),
                          SearchableEncryptedEmailQuerySet):
            errors.append(checks.Error('Default manager must use SearchableEncryptedEmailQuerySet.',
                                       obj=self, id='fernet_fields.E003'))
        if any(other is not self and other.hash_field == self.hash_field
               for other in _email_fields(self.model)):
            errors.append(checks.Error('Each searchable email needs its own hash column.',
                                       obj=self, id='fernet_fields.E004'))
        return errors


SearchableEncryptedEmailField.register_lookup(EmailEqualityLookup)
SearchableEncryptedEmailField.register_lookup(EmailInsensitiveEqualityLookup)


def _email_fields(model):
    return [field for field in model._meta.concrete_fields
            if isinstance(field, SearchableEncryptedEmailField)]


def _sync_hashes(obj, fields=None):
    added = set()
    for field in _email_fields(type(obj)):
        if fields is not None and field.name not in fields:
            if field.hash_field in fields:
                raise ValueError('Update the email instead of its hash field.')
            continue
        value = normalize_email(getattr(obj, field.attname))
        setattr(obj, field.attname, value)
        setattr(obj, field.hash_field, email_digest(field, value))
        added.add(field.hash_field)
    return added


class SearchableEncryptedEmailMixin:
    """Keep the companion index synchronized on instance saves."""

    def clean(self):
        _sync_hashes(self)
        return super().clean()

    def save(self, *args, **kwargs):
        # Django <= 5 supports positional update_fields too.
        args = list(args)
        update_fields = args[3] if len(args) > 3 else kwargs.get('update_fields')
        if update_fields is not None:
            update_fields = set(update_fields)
            if not update_fields:
                return super().save(*args, **kwargs)
        added = _sync_hashes(self, update_fields)
        if update_fields is not None:
            if len(args) > 3:
                args[3] = update_fields | added
            else:
                kwargs['update_fields'] = update_fields | added
        return super().save(*args, **kwargs)


class SearchableEncryptedEmailQuerySet(models.QuerySet):
    """Synchronize constant updates and bulk writes; reject email expressions."""

    def update(self, **kwargs):
        for field in _email_fields(self.model):
            if field.name in kwargs:
                value = normalize_email(kwargs[field.name])
                kwargs[field.name] = value
                kwargs[field.hash_field] = email_digest(field, value)
            elif field.hash_field in kwargs:
                raise ValueError('Update the email instead of its hash field.')
        return super().update(**kwargs)

    def bulk_create(self, objs, *args, **kwargs):
        objs = list(objs)
        for obj in objs:
            _sync_hashes(obj)
        if kwargs.get('update_conflicts') and kwargs.get('update_fields'):
            names = list(kwargs['update_fields'])
            for field in _email_fields(self.model):
                if field.name in names and field.hash_field not in names:
                    names.append(field.hash_field)
                elif field.hash_field in names and field.name not in names:
                    raise ValueError('Update the email instead of its hash field.')
            kwargs['update_fields'] = names
        return super().bulk_create(objs, *args, **kwargs)

    def bulk_update(self, objs, fields, batch_size=None):
        fields = list(fields)
        # Django's CASE-based implementation cannot safely hash SQL expressions.
        if not any(field.name in fields or field.hash_field in fields
                   for field in _email_fields(self.model)):
            return super().bulk_update(objs, fields, batch_size=batch_size)
        if not fields or (batch_size is not None and batch_size <= 0):
            raise ValueError('Provide fields and a positive batch_size.')
        for name in fields:
            field = self.model._meta.get_field(name)
            if not field.concrete or field.many_to_many or field.primary_key:
                raise ValueError('bulk_update requires concrete, non-primary-key fields.')
        objs = list(objs)
        if any(obj.pk is None for obj in objs):
            raise ValueError('All bulk_update objects must have a primary key.')
        count = 0
        with transaction.atomic(using=self.db):
            seen = set()
            for obj in objs:
                if obj.pk in seen:
                    continue
                seen.add(obj.pk)
                _sync_hashes(obj, set(fields))
                values = {name: getattr(obj, name) for name in fields}
                count += self.filter(pk=obj.pk).update(**values)
        return count


SearchableEncryptedEmailManager = models.Manager.from_queryset(SearchableEncryptedEmailQuerySet)
