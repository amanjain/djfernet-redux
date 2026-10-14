"""Explicit data-migration helpers for historical Django models."""
from django.core.exceptions import FieldDoesNotExist
from django.db import transaction

from .fields import EncryptedField


def encrypt_field_values(apps, schema_editor, model_label, source, target, batch_size=500):
    """Copy an existing field into a separate encrypted column, through the ORM.

    Call from RunPython after AddField and before RemoveField/RenameField. The
    original column remains intact while copying. Pause concurrent application
    writes for the migration; this helper does not synchronize them.
    """
    if source == target:
        raise ValueError('Source and target must be separate columns.')
    if not isinstance(batch_size, int) or batch_size < 1:
        raise ValueError('batch_size must be a positive integer.')
    model = apps.get_model(model_label)
    try:
        source_field = model._meta.get_field(source)
        target_field = model._meta.get_field(target)
    except FieldDoesNotExist:
        raise ValueError('Source and target must exist in the migration state.') from None
    if not source_field.concrete or source_field.is_relation:
        raise ValueError('Source must be a concrete, non-relational field.')
    if not isinstance(target_field, EncryptedField):
        raise ValueError('Target must be an encrypted field.')
    if hasattr(target_field, 'hash_field'):
        raise ValueError('Compound encrypted fields require a custom data migration.')
    alias = schema_editor.connection.alias
    queryset = model._base_manager.using(alias)
    count = 0
    with transaction.atomic(using=alias):
        for obj in queryset.only(model._meta.pk.name, source).order_by(
                model._meta.pk.name).iterator(chunk_size=batch_size):
            queryset.filter(pk=obj.pk).update(**{target: getattr(obj, source)})
            count += 1
    return count
