import json
from datetime import date, datetime
from decimal import Decimal

import django
import pytest
from cryptography.fernet import Fernet, InvalidToken

from django import forms
from django.core import serializers
from django.core.exceptions import (
    FieldError, ImproperlyConfigured, ValidationError,
)
from django.core.serializers.json import DjangoJSONEncoder
from django.db import connection, models as dj_models
from django.utils.encoding import force_bytes

import fernet_fields as fields
from django.utils.encoding import force_str

from . import models


class TestEncryptedField(object):
    def test_email_iexact_lookup_is_rejected(self, db):
        """Reproduce the lookup required by allauth (upstream #24)."""
        obj = models.EncryptedEmail.objects.create(value='person@example.com')

        assert models.EncryptedEmail.objects.get(pk=obj.pk).value == 'person@example.com'
        with pytest.raises(FieldError, match="EncryptedEmailField 'iexact'"):
            models.EncryptedEmail.objects.filter(value__iexact='PERSON@example.com').exists()

    def test_email_unique_constraint_is_rejected(self):
        """An encrypted email cannot be used as a unique login identifier."""
        with pytest.raises(ImproperlyConfigured, match='does not support unique=True'):
            fields.EncryptedEmailField(unique=True)

    def test_searchable_email_encrypts_and_supports_case_insensitive_lookup(self, db):
        from fernet_fields.email import email_digest

        model = models.EncryptedSearchableEmail
        obj = model.objects.create(value=' Person@Example.COM ')
        found = model.objects.get(value__iexact='PERSON@example.com')
        assert found.pk == obj.pk
        assert found.value == 'person@example.com'
        assert model.objects.get(value='person@example.com').pk == obj.pk
        field = model._meta.get_field('value')
        with connection.cursor() as cur:
            cur.execute('SELECT value, value_hash FROM %s WHERE id = %%s'
                        % model._meta.db_table, [obj.pk])
            token, digest = cur.fetchone()
        assert b'person@example.com' not in bytes(token)
        assert field.fernet.decrypt(bytes(token)) == b'person@example.com'
        assert digest == email_digest(field, 'person@example.com')

    def test_searchable_email_database_enforces_normalized_uniqueness(self, db):
        from django.db import IntegrityError, transaction
        from fernet_fields.email import email_digest

        model = models.EncryptedSearchableEmail
        model.objects.create(value='person@example.com')
        with pytest.raises(IntegrityError), transaction.atomic():
            model.objects.create(value='PERSON@example.com')
        assert model.objects.count() == 1
        assert email_digest(model._meta.get_field('value'), 'person@example.com')

    def test_searchable_email_updates_keep_hash_in_sync(self, db):
        from fernet_fields.email import email_digest

        model = models.EncryptedSearchableEmail
        obj = model.objects.create(value='first@example.com')
        obj.value = 'Second@Example.com'
        obj.save(update_fields=['value'])
        assert model.objects.get(value__iexact='SECOND@example.com').pk == obj.pk
        assert not model.objects.filter(value='first@example.com').exists()
        assert model.objects.filter(pk=obj.pk).update(value='third@example.com') == 1
        obj.refresh_from_db()
        assert obj.value_hash == email_digest(model._meta.get_field('value'), obj.value)
        assert model.objects.get(value='THIRD@example.com').pk == obj.pk

    def test_searchable_email_bulk_writes_keep_hash_in_sync(self, db):
        from fernet_fields.email import email_digest

        model = models.EncryptedSearchableEmail
        model.objects.bulk_create([
            model(value='first@example.com'), model(value='second@example.com')])
        objects = list(model.objects.order_by('pk'))
        for index, obj in enumerate(objects):
            obj.value = 'new%s@example.com' % index
        model.objects.bulk_update(objects, ['value'], batch_size=1)
        for index, obj in enumerate(objects):
            found = model.objects.get(value__iexact='NEW%s@example.com' % index)
            assert found.pk == obj.pk
            assert found.value_hash == email_digest(model._meta.get_field('value'), found.value)

    def test_searchable_email_rejects_unsafe_updates_and_lookups(self, db):
        from django.db.models import F
        from fernet_fields.email import SearchableEncryptedEmailField

        model = models.EncryptedSearchableEmail
        obj = model.objects.create(value='person@example.com')
        with pytest.raises(ValueError, match='expressions'):
            model.objects.filter(pk=obj.pk).update(value=F('value'))
        with pytest.raises(ValueError, match='hash'):
            model.objects.filter(pk=obj.pk).update(value_hash='tampered')
        with pytest.raises(FieldError):
            model.objects.filter(value__contains='person').exists()
        field = model._meta.get_field('value')
        _, path, args, kwargs = field.deconstruct()
        assert path == 'fernet_fields.email.SearchableEncryptedEmailField'
        assert SearchableEncryptedEmailField(*args, **kwargs).hash_field == 'value_hash'
        assert field.check() == []

    def test_searchable_email_requires_a_dedicated_hash_key(self, db, settings):
        from fernet_fields.email import email_digest

        del settings.FERNET_EMAIL_HASH_KEY
        with pytest.raises(ImproperlyConfigured, match='FERNET_EMAIL_HASH_KEY'):
            email_digest(models.EncryptedSearchableEmail._meta.get_field('value'), 'a@example.com')

    def test_searchable_email_nulls_and_multiple_columns(self, db):
        model = models.EncryptedSearchableEmail
        first = model.objects.create(value='first@example.com')
        model.objects.create(value='second@example.com')
        assert model.objects.filter(optional=None).count() == 2
        first.optional = 'OPTIONAL@example.com'
        first.save(update_fields=['optional'])
        assert model.objects.get(optional__iexact='optional@example.com').pk == first.pk
        first.optional = None
        first.save(update_fields=['optional'])
        assert model.objects.filter(optional__isnull=True).count() == 2
        first.refresh_from_db()
        assert first.optional_hash is None

    def test_searchable_email_hash_is_independent_of_encryption_rotation(self, db, settings):
        from fernet_fields.email import email_digest

        field = models.EncryptedSearchableEmail._meta.get_field('value')
        digest = email_digest(field, 'person@example.com')
        token = field.fernet.encrypt(b'person@example.com')
        settings.FERNET_KEYS = ['new-encryption-key', 'secret']
        rotated = field.clone()
        rotated.model = field.model
        rotated.set_attributes_from_name(field.name)
        assert email_digest(rotated, 'person@example.com') == digest
        assert rotated.from_db_value(token, None, connection) == 'person@example.com'

    def test_searchable_email_full_clean_checks_uniqueness(self, db):
        from fernet_fields.email import email_digest

        model = models.EncryptedSearchableEmail
        first = model(value='person@example.com')
        first.full_clean()
        assert first.value_hash == email_digest(model._meta.get_field('value'), first.value)
        first.save()
        duplicate = model(value='PERSON@example.com')
        with pytest.raises(ValidationError):
            duplicate.full_clean()

    def test_searchable_email_checks_invalid_hash_configuration(self, settings):
        from fernet_fields.email import email_digest

        field = models.EncryptedSearchableEmail._meta.get_field('value')
        invalid = field.clone()
        invalid.model = field.model
        invalid.set_attributes_from_name(field.name)
        invalid.hash_field = 'missing'
        assert 'fernet_fields.E001' in [error.id for error in invalid.check()]
        settings.FERNET_EMAIL_HASH_KEY = 'too-short'
        with pytest.raises(ImproperlyConfigured):
            email_digest(field, 'person@example.com')

    def test_searchable_email_historical_backfill_populates_both_columns(self, db):
        from django.db.migrations.state import ModelState, ProjectState
        from django.db.migrations.writer import MigrationWriter
        from fernet_fields.email import email_digest

        state = ProjectState()
        state.add_model(ModelState.from_model(models.EncryptedSearchableEmail))
        historical = state.apps.get_model('test', 'EncryptedSearchableEmail')
        field = historical._meta.get_field('value')
        code, imports = MigrationWriter.serialize(field)
        assert "hash_field='value_hash'" in code
        assert 'import fernet_fields.email' in imports
        obj = models.EncryptedSearchableEmail.objects.create(value='person@example.com')
        # Historical base-manager writes bypass the custom queryset update hooks.
        historical._base_manager.filter(pk=obj.pk).update(
            value='NEXT@example.com', value_hash=email_digest(field, 'NEXT@example.com'))
        found = models.EncryptedSearchableEmail.objects.get(value__iexact='next@example.com')
        assert found.pk == obj.pk

    def test_key_from_settings(self, settings):
        """If present, use settings.FERNET_KEYS."""
        settings.FERNET_KEYS = ['secret']
        f = fields.EncryptedTextField()

        assert f.keys == settings.FERNET_KEYS

    def test_alter_plaintext_field_does_not_encrypt_existing_rows(self, transactional_db):
        """A real AlterField changes the column but does not encrypt old data."""
        from django.db.migrations import AlterField
        from django.db.migrations.state import ModelState, ProjectState

        # Render the existing model as it would exist in an older migration.
        plain_state = ProjectState()
        plain_model_state = ModelState(
            'test', 'EncryptedText',
            [('id', models.EncryptedText._meta.pk.clone()),
             ('value', dj_models.TextField())],
        )
        plain_state.add_model(plain_model_state)
        legacy_model = plain_state.apps.get_model('test', 'EncryptedText')
        plain_field = legacy_model._meta.get_field('value')
        encrypted_field = models.EncryptedText._meta.get_field('value')
        with connection.schema_editor() as editor:
            editor.alter_field(models.EncryptedText, encrypted_field, plain_field)
        try:
            obj = legacy_model.objects.create(value='existing private data')
            encrypted_state = plain_state.clone()
            operation = AlterField('encryptedtext', 'value', fields.EncryptedTextField())
            operation.state_forwards('test', encrypted_state)
            with connection.schema_editor() as editor:
                operation.database_forwards('test', editor, plain_state, encrypted_state)

            migrated_model = encrypted_state.apps.get_model('test', 'EncryptedText')
            # The migration leaves plaintext: SQLite may return str, PostgreSQL bytes.
            # Accept the existing TypeError or the clearer decryption error: neither
            # repairs the missing encryption, including after input handling is fixed.
            with pytest.raises((TypeError, fields.DecryptionError)):
                migrated_model.objects.get(pk=obj.pk)
            with connection.cursor() as cur:
                cur.execute(
                    'SELECT value FROM %s WHERE id = %%s'
                    % models.EncryptedText._meta.db_table, [obj.pk],
                )
                stored = cur.fetchone()[0]
            assert force_bytes(stored) == b'existing private data'
        finally:
            # Restore the original table even if migration or assertion fails.
            with connection.schema_editor() as editor:
                editor.alter_field(models.EncryptedText, plain_field, encrypted_field)

    def test_plaintext_data_migration_encrypts_existing_rows(self, transactional_db):
        from django.db.migrations import AddField, RemoveField, RenameField, RunPython
        from django.db.migrations.state import ModelState, ProjectState
        from fernet_fields.migrations import encrypt_field_values

        state = ProjectState()
        state.add_model(ModelState(
            'test', 'EncryptedText',
            [('id', models.EncryptedText._meta.pk.clone()),
             ('value', dj_models.TextField(null=True))],
        ))
        legacy_model = state.apps.get_model('test', 'EncryptedText')
        with connection.schema_editor() as editor:
            editor.alter_field(
                models.EncryptedText, models.EncryptedText._meta.get_field('value'),
                legacy_model._meta.get_field('value'))
        try:
            values = ['existing private data', 'café', '', None]
            for value in values:
                legacy_model.objects.create(value=value)

            def encrypt_values(apps, schema_editor):
                encrypt_field_values(
                    apps, schema_editor, 'test.EncryptedText',
                    'value', 'encrypted_value', batch_size=1)

            operations = [
                AddField('encryptedtext', 'encrypted_value',
                         fields.EncryptedTextField(null=True)),
                RunPython(encrypt_values),
                RemoveField('encryptedtext', 'value'),
                RenameField('encryptedtext', 'encrypted_value', 'value'),
            ]
            for operation in operations:
                new_state = state.clone()
                operation.state_forwards('test', new_state)
                with connection.schema_editor() as editor:
                    operation.database_forwards('test', editor, state, new_state)
                state = new_state

            migrated_model = state.apps.get_model('test', 'EncryptedText')
            assert list(migrated_model.objects.order_by('pk').values_list(
                'value', flat=True)) == values
            field = migrated_model._meta.get_field('value')
            with connection.cursor() as cur:
                cur.execute('SELECT value FROM %s ORDER BY id'
                            % models.EncryptedText._meta.db_table)
                stored = [row[0] for row in cur.fetchall()]
            for raw, value in zip(stored, values):
                if value is None:
                    assert raw is None
                else:
                    assert field.fernet.decrypt(bytes(raw)).decode() == value
                    assert bytes(raw) != value.encode()
            with connection.cursor() as cur:
                columns = connection.introspection.get_table_description(
                    cur, models.EncryptedText._meta.db_table)
            assert [column.name for column in columns] == ['id', 'value']
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(models.EncryptedText)
                editor.create_model(models.EncryptedText)

    def test_encryption_migration_rolls_back_if_a_value_cannot_be_copied(self, transactional_db):
        from django.db.migrations import AddField
        from django.db.migrations.state import ModelState, ProjectState
        from fernet_fields.migrations import encrypt_field_values

        state = ProjectState()
        state.add_model(ModelState.from_model(models.EncryptedText))
        operation = AddField('encryptedtext', 'integer_value',
                             fields.EncryptedIntegerField(null=True))
        new_state = state.clone()
        operation.state_forwards('test', new_state)
        model = new_state.apps.get_model('test', 'EncryptedText')
        target = model._meta.get_field('integer_value')
        with connection.schema_editor() as editor:
            operation.database_forwards('test', editor, state, new_state)
        try:
            model.objects.create(value='1')
            model.objects.create(value='not-an-integer')
            with connection.schema_editor() as editor:
                with pytest.raises(ValueError):
                    encrypt_field_values(new_state.apps, editor, 'test.EncryptedText',
                                         'value', 'integer_value', batch_size=1)
            assert list(model.objects.order_by('pk').values_list(
                'integer_value', flat=True)) == [None, None]
            assert list(model.objects.order_by('pk').values_list(
                'value', flat=True)) == ['1', 'not-an-integer']
        finally:
            with connection.schema_editor() as editor:
                editor.remove_field(model, target)

    def test_fallback_to_secret_key(self, settings):
        """If no FERNET_KEY setting, use SECRET_KEY."""
        f = fields.EncryptedTextField()

        assert f.keys == [settings.SECRET_KEY]

    @pytest.mark.parametrize('bad_value', [
        b'legacy plaintext',
        Fernet(Fernet.generate_key()).encrypt(b'wrong-key secret'),
        b'gAAAA-truncated-token',
    ], ids=['plaintext', 'different-key', 'truncated-token'])
    def test_bad_row_interrupts_whole_queryset(self, db, bad_value):
        """Reproduce why a bulk ORM scan cannot audit a damaged table."""
        first = models.EncryptedText.objects.create(value='healthy first')
        broken = models.EncryptedText.objects.create(value='placeholder')
        last = models.EncryptedText.objects.create(value='healthy last')
        with connection.cursor() as cur:
            cur.execute(
                'UPDATE %s SET value = %%s WHERE id = %%s'
                % models.EncryptedText._meta.db_table,
                [connection.Database.Binary(bad_value), broken.pk],
            )

        with pytest.raises(fields.DecryptionError) as exc:
            list(models.EncryptedText.objects.order_by('pk'))

        # The failing scan leaves healthy rows readable and the bad row intact.
        assert models.EncryptedText.objects.get(pk=first.pk).value == 'healthy first'
        assert models.EncryptedText.objects.get(pk=last.pk).value == 'healthy last'
        assert models.EncryptedText.objects.count() == 3
        with connection.cursor() as cur:
            cur.execute(
                'SELECT value FROM %s WHERE id = %%s'
                % models.EncryptedText._meta.db_table,
                [broken.pk],
            )
            assert bytes(cur.fetchone()[0]) == bad_value
        assert 'test.EncryptedText.value' in str(exc.value)
        assert bad_value.decode('ascii') not in str(exc.value)

        from fernet_fields.audit import audit_encrypted_fields

        failures = list(audit_encrypted_fields(
            models.EncryptedText.objects.order_by('pk'), batch_size=1))
        assert len(failures) == 1
        assert failures[0].model == 'test.EncryptedText'
        assert failures[0].pk == broken.pk
        assert failures[0].field == 'value'
        assert failures[0].reason == 'cannot-decrypt'
        assert bad_value.decode('ascii') not in repr(failures)
        assert list(audit_encrypted_fields(
            models.EncryptedText.objects.filter(pk=last.pk))) == []

    @pytest.mark.parametrize('options', [
        {'batch_size': 0}, {'fields': ['id']}, {'fields': ['missing']},
    ])
    def test_audit_rejects_invalid_options(self, db, options):
        from fernet_fields.audit import audit_encrypted_fields

        with pytest.raises(ValueError):
            list(audit_encrypted_fields(models.EncryptedText.objects.all(), **options))

    def test_audit_empty_queryset(self, db):
        from fernet_fields.audit import audit_encrypted_fields

        assert list(audit_encrypted_fields(models.EncryptedText.objects.none())) == []

    def test_audit_reports_invalid_decrypted_values_without_exposing_them(self, db):
        from fernet_fields.audit import audit_encrypted_fields

        obj = models.EncryptedJSON.objects.create(value={'private': 'original'})
        field = models.EncryptedJSON._meta.get_field('value')
        token = field.fernet.encrypt(b'private-invalid-json')
        with connection.cursor() as cur:
            cur.execute('UPDATE %s SET value = %%s WHERE id = %%s'
                        % models.EncryptedJSON._meta.db_table,
                        [connection.Database.Binary(token), obj.pk])
        failures = list(audit_encrypted_fields(models.EncryptedJSON.objects.all()))
        assert len(failures) == 1
        assert failures[0].reason == 'invalid-value'
        assert 'private-invalid-json' not in repr(failures)
        assert list(audit_encrypted_fields(models.EncryptedJSON.objects.none())) == []
        # Filtering must be honored; audits must not accidentally scan all rows.
        assert list(audit_encrypted_fields(models.EncryptedJSON.objects.filter(pk=-1))) == []

    def test_key_rotation(self, settings):
        """Can supply multiple `keys` for key rotation."""
        settings.FERNET_KEYS = ['key1', 'key2']
        f = fields.EncryptedTextField()

        enc1 = Fernet(f.fernet_keys[0]).encrypt(b'enc1')
        enc2 = Fernet(f.fernet_keys[1]).encrypt(b'enc2')

        assert f.fernet.decrypt(enc1) == b'enc1'
        assert f.fernet.decrypt(enc2) == b'enc2'

    @pytest.mark.parametrize('value', ['private-invalid-token', 'café-private-value'])
    def test_invalid_text_input_has_decryption_error(self, value):
        field = models.EncryptedText._meta.get_field('value')

        with pytest.raises(fields.DecryptionError) as exc:
            field.from_db_value(value, None, connection)

        assert 'test.EncryptedText.value' in str(exc.value)
        assert value not in str(exc.value)

    @pytest.mark.parametrize('value', [10 ** 12, [1, 2, 3], object()])
    def test_invalid_storage_types_have_decryption_error(self, value):
        field = models.EncryptedText._meta.get_field('value')
        with pytest.raises(fields.DecryptionError):
            field.from_db_value(value, None, connection)

    def test_existing_text_column_can_be_read(self, transactional_db):
        encrypted = models.EncryptedText._meta.get_field('value')
        plain = dj_models.TextField()
        plain.set_attributes_from_name('value')
        plain.model = models.EncryptedText
        with connection.schema_editor() as editor:
            editor.alter_field(models.EncryptedText, encrypted, plain)
        try:
            obj = models.EncryptedText.objects.create(value='private legacy value')
            with connection.cursor() as cur:
                cur.execute('UPDATE %s SET value = CAST(value AS TEXT) WHERE id = %%s'
                            % models.EncryptedText._meta.db_table, [obj.pk])
                cur.execute('SELECT value FROM %s WHERE id = %%s'
                            % models.EncryptedText._meta.db_table, [obj.pk])
                assert isinstance(cur.fetchone()[0], str)
            assert models.EncryptedText.objects.get(pk=obj.pk).value == 'private legacy value'
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(models.EncryptedText)
                editor.create_model(models.EncryptedText)

    def test_no_hkdf(self, settings):
        """Can set FERNET_USE_HKDF=False to avoid HKDF."""
        settings.FERNET_USE_HKDF = False
        k1 = Fernet.generate_key()
        settings.FERNET_KEYS = [k1]
        f = fields.EncryptedTextField()
        fernet = Fernet(k1)

        assert fernet.decrypt(f.fernet.encrypt(b'foo')) == b'foo'

    @pytest.mark.parametrize('key', ['primary_key', 'db_index', 'unique'])
    def test_not_allowed(self, key):
        with pytest.raises(ImproperlyConfigured):
            fields.EncryptedIntegerField(**{key: True})

    def test_default_admin_form_displays_decrypted_value(self, db):
        """Encryption at rest does not mask the existing admin edit form."""
        from django.contrib.admin import AdminSite, ModelAdmin

        obj = models.EncryptedText.objects.create(value='private-admin-value')
        obj.refresh_from_db()
        model_admin = ModelAdmin(models.EncryptedText, AdminSite())
        form_class = model_admin.get_form(None, obj=obj)
        form = form_class(instance=obj)

        assert obj.value == 'private-admin-value'
        assert form['value'].value() == 'private-admin-value'
        assert 'private-admin-value' in str(form['value'])
        with connection.cursor() as cur:
            cur.execute(
                'SELECT value FROM %s WHERE id = %%s'
                % models.EncryptedText._meta.db_table, [obj.pk],
            )
            assert b'private-admin-value' not in bytes(cur.fetchone()[0])

    def test_masked_admin_hides_values_in_forms_and_lists(self, db):
        from django.contrib.admin import AdminSite, ModelAdmin
        from fernet_fields.admin import MaskedEncryptedAdminMixin

        class MaskedAdmin(MaskedEncryptedAdminMixin, ModelAdmin):
            list_display = ('id', 'value')
            fieldsets = ((None, {'fields': (('id', 'value'),)}),)
            readonly_fields = ('id',)

        obj = models.EncryptedText.objects.create(value='private-admin-value')
        model_admin = MaskedAdmin(models.EncryptedText, AdminSite())
        form_class = model_admin.get_form(None, obj=obj)
        assert 'value' not in form_class.base_fields
        assert model_admin.get_readonly_fields(None, obj) == ('id', '_masked_value')
        assert model_admin.get_list_display(None) == ('id', '_masked_value')
        assert model_admin.get_fieldsets(None, obj)[0][1]['fields'] == (
            ('id', '_masked_value'),)
        assert model_admin._masked_value(obj) == '********'
        # Saving the form must not clear the hidden encrypted value.
        form = form_class({}, instance=obj)
        assert form.is_valid()
        form.save()
        obj.refresh_from_db()
        assert obj.value == 'private-admin-value'

    def test_masked_admin_does_not_reuse_a_custom_display_callback(self, db):
        from django.contrib.admin import AdminSite, ModelAdmin
        from fernet_fields.admin import MaskedEncryptedAdminMixin

        class CustomAdmin(MaskedEncryptedAdminMixin, ModelAdmin):
            list_display = ('id', 'value')

            def _masked_value(self, obj):
                return obj.value

        obj = models.EncryptedText.objects.create(value='private-admin-value')
        model_admin = CustomAdmin(models.EncryptedText, AdminSite())
        name = model_admin.get_list_display(None)[1]
        assert getattr(model_admin, name)(obj) == '********'
        assert model_admin.get_list_display(None)[1] == name
        assert 'value' not in model_admin.get_form(None, obj=obj).base_fields

    def test_get_integer_field_validators(self):
        f = fields.EncryptedIntegerField()

        # Raises no error
        f.validators


@pytest.mark.parametrize(
    'model,vals',
    [
        (models.EncryptedText, ['foo', 'bar']),
        (models.EncryptedChar, ['one', 'two']),
        (models.EncryptedEmail, ['a@example.com', 'b@example.com']),
        (models.EncryptedInt, [1, 2]),
        (models.EncryptedBigInt, [2 ** 40, -(2 ** 40)]),
        (models.EncryptedDate, [date(2015, 2, 5), date(2015, 2, 8)]),
        (
            models.EncryptedDateTime,
            [datetime(2015, 2, 5, 15), datetime(2015, 2, 8, 16)],
        ),
    ],
)
class TestEncryptedFieldQueries(object):
    def test_insert(self, db, model, vals):
        """Data stored in DB is actually encrypted."""
        field = model._meta.get_field('value')
        model.objects.create(value=vals[0])
        with connection.cursor() as cur:
            cur.execute('SELECT value FROM %s' % model._meta.db_table)
            data = [
                force_str(field.fernet.decrypt(force_bytes(r[0])))
                for r in cur.fetchall()
            ]

        assert list(map(field.to_python, data)) == [vals[0]]

    def test_insert_and_select(self, db, model, vals):
        """Data round-trips through insert and select."""
        model.objects.create(value=vals[0])
        found = model.objects.get()

        assert found.value == vals[0]

    @pytest.mark.parametrize('encoding', ['ascii', 'postgres-hex'])
    def test_read_text_encoded_ciphertext(self, db, model, vals, encoding):
        obj = model.objects.create(value=vals[0])
        field = model._meta.get_field('value')
        with connection.cursor() as cur:
            cur.execute(
                'SELECT value FROM %s WHERE id = %%s' % model._meta.db_table,
                [obj.pk],
            )
            token = bytes(cur.fetchone()[0])

        # Some legacy schemas return the same token as text rather than bytes.
        text = token.decode('ascii') if encoding == 'ascii' else '\\x' + token.hex()
        assert field.from_db_value(text, None, connection) == vals[0]

    def test_update_and_select(self, db, model, vals):
        """Data round-trips through update and select."""
        model.objects.create(value=vals[0])
        model.objects.update(value=vals[1])
        found = model.objects.get()

        assert found.value == vals[1]

    def test_lookups_raise_field_error(self, db, model, vals):
        """Lookups are not allowed (they cannot succeed)."""
        model.objects.create(value=vals[0])
        field_name = model._meta.get_field('value').__class__.__name__
        lookups = set(dj_models.Field.class_lookups) - set(['isnull'])

        for lookup in lookups:
            with pytest.raises(FieldError) as exc:
                model.objects.get(**{'value__' + lookup: vals[0]})
            assert field_name in str(exc.value)
            assert lookup in str(exc.value)
            assert 'does not support lookups' in str(exc.value)


def test_nullable(db):
    """Encrypted/dual/hash field can be nullable."""
    models.EncryptedNullable.objects.create(value=None)
    found = models.EncryptedNullable.objects.get()

    assert found.value is None


def test_isnull_false_lookup(db):
    """isnull False lookup succeeds on nullable fields"""
    test_val = 3
    models.EncryptedNullable.objects.create(value=None)
    models.EncryptedNullable.objects.create(value=test_val)
    found = models.EncryptedNullable.objects.get(value__isnull=False)

    assert found.value == test_val


def test_isnull_true_lookup(db):
    """isnull True lookup succeeds on nullable fields"""
    test_val = 3
    models.EncryptedNullable.objects.create(value=None)
    models.EncryptedNullable.objects.create(value=test_val)
    found = models.EncryptedNullable.objects.get(value__isnull=True)

    assert found.value is None


def test_decryption_error_names_field_and_hides_ciphertext(db, settings):
    """A value from another key raises a helpful DecryptionError."""
    token = Fernet(Fernet.generate_key()).encrypt(b'private')
    with connection.cursor() as cur:
        cur.execute(
            'INSERT INTO %s (value) VALUES (%%s)'
            % models.EncryptedText._meta.db_table,
            [connection.Database.Binary(token)],
        )

    with pytest.raises(fields.DecryptionError) as exc:
        models.EncryptedText.objects.get()

    message = str(exc.value)
    assert isinstance(exc.value, InvalidToken)
    assert 'test.EncryptedText.value' in message
    assert 'FERNET_KEYS' in message
    assert token.decode() not in message


def test_decryption_error_on_unencrypted_data(db):
    """Plaintext left in an encrypted column raises DecryptionError."""
    with connection.cursor() as cur:
        cur.execute(
            'INSERT INTO %s (value) VALUES (%%s)'
            % models.EncryptedChar._meta.db_table,
            [connection.Database.Binary(b'not encrypted')],
        )

    with pytest.raises(fields.DecryptionError) as exc:
        models.EncryptedChar.objects.get()

    assert 'test.EncryptedChar.value' in str(exc.value)


class TestEncryptedBinaryField(object):
    @pytest.mark.parametrize('make', [bytes, bytearray, memoryview])
    def test_round_trip_keeps_raw_bytes(self, db, make):
        raw = bytes(range(256))
        models.EncryptedBinary.objects.create(value=make(raw))

        assert models.EncryptedBinary.objects.get().value == raw

    def test_stored_bytes_are_encrypted(self, db):
        field = models.EncryptedBinary._meta.get_field('value')
        models.EncryptedBinary.objects.create(value=b'\x00secret')
        with connection.cursor() as cur:
            cur.execute(
                'SELECT value FROM %s' % models.EncryptedBinary._meta.db_table)
            stored = bytes(cur.fetchone()[0])

        assert b'secret' not in stored
        assert field.fernet.decrypt(stored) == b'\x00secret'


class TestEncryptedJSONField(object):
    @pytest.mark.parametrize('value', [
        {'plan': 'growth', 'seats': 12, 'flags': [True, None, 1.5]},
        ['nested', {'tags': ['a', 'b']}],
        'a plain string',
        '123',
        42,
        False,
        {'city': 'Zürich', 'note': '☕'},
    ])
    def test_round_trip(self, db, value):
        models.EncryptedJSON.objects.create(value=value)

        assert models.EncryptedJSON.objects.get().value == value

    def test_stored_value_is_encrypted_json_text(self, db):
        field = models.EncryptedJSON._meta.get_field('value')
        models.EncryptedJSON.objects.create(value={'api_key': 'sk-live-1'})
        with connection.cursor() as cur:
            cur.execute(
                'SELECT value FROM %s' % models.EncryptedJSON._meta.db_table)
            stored = bytes(cur.fetchone()[0])

        assert b'sk-live-1' not in stored
        assert json.loads(field.fernet.decrypt(stored)) == {
            'api_key': 'sk-live-1'}

    def test_reads_json_text_written_by_encrypted_text_field(self, db):
        """Values from an EncryptedTextField holding JSON text read back."""
        text_field = fields.EncryptedTextField()
        token = text_field.fernet.encrypt(
            json.dumps({'city': 'Zürich'}, ensure_ascii=False).encode())
        with connection.cursor() as cur:
            cur.execute(
                'INSERT INTO %s (value) VALUES (%%s)'
                % models.EncryptedJSON._meta.db_table,
                [connection.Database.Binary(token)],
            )

        assert models.EncryptedJSON.objects.get().value == {'city': 'Zürich'}

    def test_none_is_sql_null(self, db):
        models.EncryptedJSON.objects.create(value=None)

        assert models.EncryptedJSON.objects.get(value__isnull=True).value \
            is None

    def test_encoder_serializes_decimals_and_datetimes(self, db):
        models.EncryptedJSONWithEncoder.objects.create(
            value={'amount': Decimal('19.99'), 'at': datetime(2026, 1, 2, 3)})

        assert models.EncryptedJSONWithEncoder.objects.get().value == {
            'amount': '19.99', 'at': '2026-01-02T03:00:00'}

    def test_decoder_is_used_when_reading(self, db):
        class DecimalDecoder(json.JSONDecoder):
            def __init__(self, **kwargs):
                kwargs['parse_float'] = Decimal
                super(DecimalDecoder, self).__init__(**kwargs)

        field = fields.EncryptedJSONField(decoder=DecimalDecoder)
        token = field.fernet.encrypt(b'{"amount": 19.99}')

        assert field.from_db_value(token, None, connection) == {
            'amount': Decimal('19.99')}

    def test_lookups_raise_field_error(self, db):
        with pytest.raises(FieldError) as exc:
            models.EncryptedJSON.objects.get(value__exact={'a': 1})

        assert 'does not support lookups' in str(exc.value)

    def test_unserializable_value_fails_validation(self):
        obj = models.EncryptedJSON(value={'when': datetime(2026, 1, 2)})

        with pytest.raises(ValidationError) as exc:
            obj.full_clean()

        assert exc.value.message_dict == {
            'value': ['Value must be valid JSON.']}

    def test_deconstruct_keeps_encoder_and_decoder(self):
        field = fields.EncryptedJSONField(
            encoder=DjangoJSONEncoder, decoder=json.JSONDecoder)

        name, path, args, kwargs = field.deconstruct()

        assert path == 'fernet_fields.fields.EncryptedJSONField'
        assert kwargs == {
            'encoder': DjangoJSONEncoder, 'decoder': json.JSONDecoder}
        assert fields.EncryptedJSONField().deconstruct()[3] == {}

    def test_formfield_is_a_json_field(self):
        field = models.EncryptedJSONWithEncoder._meta.get_field('value')
        if django.VERSION < (3, 1):
            # forms.JSONField arrived in Django 3.1.
            with pytest.raises(AttributeError):
                field.formfield()
            return

        formfield = field.formfield()

        assert isinstance(formfield, forms.JSONField)
        assert formfield.encoder is DjangoJSONEncoder
        assert formfield.prepare_value({'a': 1}) == '{"a": 1}'

    def test_serializes_as_json_not_python_repr(self, db):
        models.EncryptedJSON.objects.create(value={'plan': 'growth'})

        data = json.loads(
            serializers.serialize('json', models.EncryptedJSON.objects.all()))

        assert data[0]['fields'] == {'value': {'plan': 'growth'}}
