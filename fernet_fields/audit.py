"""Read-only inspection of encrypted columns, without ORM value conversion."""
from typing import NamedTuple

from django.core.exceptions import FieldDoesNotExist
from django.db import connections
from django.core.exceptions import EmptyResultSet

from .fields import DecryptionError, EncryptedField


class AuditFailure(NamedTuple):
    model: str
    pk: object
    field: str
    reason: str


def audit_encrypted_fields(queryset, fields=None, batch_size=500):
    """Yield identifiers of unreadable fields; never return stored/private values.

    Wrong keys and corrupt ciphertext both produce ``cannot-decrypt``. The
    function cannot distinguish them, recover values, or modify the database.
    """
    if not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError('batch_size must be a positive integer.')
    model = queryset.model
    if fields is None:
        selected = [f for f in model._meta.concrete_fields if isinstance(f, EncryptedField)]
    else:
        selected = []
        for name in fields:
            try:
                field = model._meta.get_field(name)
            except FieldDoesNotExist:
                raise ValueError('Unknown encrypted field: %s.' % name) from None
            if not isinstance(field, EncryptedField) or not field.concrete:
                raise ValueError('%s is not a concrete encrypted field.' % name)
            selected.append(field)
    if not selected:
        return
    # Invalid key configuration is an operator error, not corrupt row data.
    for field in selected:
        field.fernet
    connection = connections[queryset.db]
    values = queryset.values_list(model._meta.pk.name, *[f.name for f in selected])
    try:
        sql, params = values.query.get_compiler(using=queryset.db).as_sql()
    except EmptyResultSet:
        return
    with connection.cursor() as cursor:
        cursor.execute(sql, params)
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break
            for row in rows:
                for field, raw in zip(selected, row[1:]):
                    if raw is None:
                        continue
                    try:
                        field.from_db_value(raw, None, connection)
                    except DecryptionError:
                        reason = 'cannot-decrypt'
                    except TypeError:
                        reason = 'invalid-storage'
                    except (ValueError, UnicodeError):
                        reason = 'invalid-value'
                    else:
                        continue
                    yield AuditFailure(model._meta.label, row[0], field.name, reason)
