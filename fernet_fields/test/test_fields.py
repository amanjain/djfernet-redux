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
    def test_key_from_settings(self, settings):
        """If present, use settings.FERNET_KEYS."""
        settings.FERNET_KEYS = ['secret']
        f = fields.EncryptedTextField()

        assert f.keys == settings.FERNET_KEYS

    def test_fallback_to_secret_key(self, settings):
        """If no FERNET_KEY setting, use SECRET_KEY."""
        f = fields.EncryptedTextField()

        assert f.keys == [settings.SECRET_KEY]

    def test_key_rotation(self, settings):
        """Can supply multiple `keys` for key rotation."""
        settings.FERNET_KEYS = ['key1', 'key2']
        f = fields.EncryptedTextField()

        enc1 = Fernet(f.fernet_keys[0]).encrypt(b'enc1')
        enc2 = Fernet(f.fernet_keys[1]).encrypt(b'enc2')

        assert f.fernet.decrypt(enc1) == b'enc1'
        assert f.fernet.decrypt(enc2) == b'enc2'

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
