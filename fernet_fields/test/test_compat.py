"""Data written by the released libraries must keep decrypting.

The tokens were produced by django-fernet-fields 0.6 and djfernet 0.8.1
(installed from PyPI) with SECRET_KEY = 'secret', the test settings' key.
"""
import importlib
from datetime import date, datetime

import pytest
from django.db import connection
from django.test import override_settings

import fernet_fields as fields
from fernet_fields import hkdf

from . import models

# HKDF key derived from SECRET_KEY 'secret' by both libraries.
DERIVED_KEY = b'eWHXcUXxud6rRb_yANSEsNsfZ0YFs2P6OTSzfFeL55E='
# The same key with DJFERNET_PREFIX = b'djfernet' (djfernet < 0.8 data).
DERIVED_KEY_DJFERNET_PREFIX = b'kdWy3NEsGqzjvSY7D4-nPUey5BqbLz4TbHbDwhH1WHw='

DJANGO_FERNET_FIELDS_0_6 = {
    'text': (
        b'gAAAAABqy1dgOopMdLHBvPqKO8l0y_Fc4L-ZK21dZJj7jIzXhkvfH7bfznR8'
        b'N4CGxCarvQjOgRBGaoQmkkKTo7Nm4ukZp4oamQ=='
    ),
    'char': (
        b'gAAAAABqy1dhoFtR47CD3LAaZ-cGm08psusx7FwuFWkSkW6oxlhXXidqTQUG'
        b'vBVioPyV9gB0feN8c6fl4t4Lg_50PXSm5UcE-g=='
    ),
    'email': (
        b'gAAAAABqy1dhR-CvGmwAo16j8rX1AwWjbUzI42USttVwBRxjCcOwjnc9UjzT'
        b'1EmRA7f0QNV-JW9xdwb8R7NmZhsJVm6aHuTScg=='
    ),
    'int': (
        b'gAAAAABqy1dh5Bs-2Nf4pipNwdWFbnH4rzNqLZ1wFAcxOVdPVSOoZuC-0oxT'
        b'SGNf_f6qgtoAU_AkiK3Qwkmv8vLxzj5ND--DYg=='
    ),
    'date': (
        b'gAAAAABqy1dhj_d4vY4eWDROFZWf-tc2S81gaEFO4Di4n3c7IPMqRLteeu0U'
        b'HCszeQ7o29DVCbRIuE3UXOd6XOcot1_-NlaisQ=='
    ),
    'datetime': (
        b'gAAAAABqy1dhJ0McWpAkGDEs5n-T58A5gnFDDc3_wLzGC1dolUagB4vv2hen'
        b'mk9Ynb9Jzzx-8vtJWr9vbiyD0N84K-cCMv2nX-SV4yQJm2DcNx8T8xLesEg='
    ),
}

DJFERNET_0_8_1 = {
    'text': (
        b'gAAAAABqy1diUV2AZfSgdTgp2ZIhpwy8eRUz0Vo0QxSZNWg7b9fz2f7VYDcR'
        b'j4qwS_oPSloN7xXfLBobJRpBF75X2bpd05K8ig=='
    ),
    'char': (
        b'gAAAAABqy1di4GEdDY-C2gvY_NTqVTSvFLhhMTPrZ5tEsLLjN6We37xH_g_k'
        b'stNjD9bwPB5aFspnJ2PpC4cDGKdHWyw-kOd7oQ=='
    ),
    'email': (
        b'gAAAAABqy1diTz7jId8rjkfYTrNs3EhjAb0r0Z32q4lMd7pIndSfLKRS9m0M'
        b'6dFEavZPxKPNVgQmEvB3M7FvB0ZpiIBv7jfH1A=='
    ),
    'int': (
        b'gAAAAABqy1diZH_7R90DSwPcDBP-v9sAoz-fQKkA1ZxyJ6RUDJgPCJgVCefR'
        b'exacueT4YFK0QZWgaBPrXMr-2cSDD8btX1NiLg=='
    ),
    'date': (
        b'gAAAAABqy1di9uOyedSC7737pI97yACAJH_0DOUT-Z325ZuU7lNqm_6-cu2X'
        b'0VFs2EEQYimKLgEUtqOTJyFaPZ_ik24PnFiF7w=='
    ),
    'datetime': (
        b'gAAAAABqy1diAAfamFjVTWwcSwfIUdzuBWr4cfwgmQBA95NK_XUPcynOe_pv'
        b'UXhDl_ePojzYxSHh7p635RMhryVMSeHD38GdTAs3AlSUVuwZMbK1qZmKdcg='
    ),
    'binary': (
        b'gAAAAABqy1di0uZSbj9m5CSL18fuPZm0bBdCS4Yta4JulwpMt2y9kR2riVNW'
        b'_yh7uWPENqmopXJuywLjPuOi5ZlVrgds_lOehQ=='
    ),
}

DJFERNET_0_8_1_DJFERNET_PREFIX = {
    'text': (
        b'gAAAAABqy1dmLOJFfdoQ6E3tCeIW5ppNHnhX9waRJSE-B2yfwyWLpZzVE3TY'
        b'h9CV3TOeBlKB2aHfG87Q5oA1i6lxow2GCkixjg=='
    ),
    'char': (
        b'gAAAAABqy1dm7fY9D_sL5xLo2dTnRt_XWLcfBMjihvomrIppGpc3NRu03tZe'
        b'DJmiE__07i1V9esiAgr5yPjL7S64pD8SV4XMaA=='
    ),
    'email': (
        b'gAAAAABqy1dm8O3CZYUiJX6BmG1pxQ0TmZBVnwWhRqsbMQvXvLTkk7nt3B1O'
        b'Fo02t78bc8k-A6Tp3lxtMySe83cIkZ6Nvmh6Cw=='
    ),
    'int': (
        b'gAAAAABqy1dmNwRgCojxsT0eq_xc9e73dWr2u3GVoSeeIbZEUkCCLYGrZziX'
        b'tnngjyThBctFqOK_-WAHpzJgypfs7am6e9XZ6g=='
    ),
    'date': (
        b'gAAAAABqy1dmoK8WmZYP1EY-3JY9_w48JTVp4K3I30lvUrul2O1UaH4dLCok'
        b'SwB7jIn1b48hJjaOcGBjRBoS9BIFNqgTqAFBLQ=='
    ),
    'datetime': (
        b'gAAAAABqy1dm1iYpLeDbBPV9QOEQYCB3u_6g-MNaLTN8TreGf8k3yGtSUWBy'
        b'-LwEpNb2q8GBpXiLLy8vyYwua1lBcxD5Ako7yHrj7YbCnSpJn3U2EsXnuIk='
    ),
    'binary': (
        b'gAAAAABqy1dmqqdY2O7SLnq9uDn0PZC3nQ_rrOnr6KU0ydtYESRzZOtFo-cj'
        b'PjZkYwUv_k2oLIdwefEv5FoTsKVN9-LD5reClQ=='
    ),
}

EXPECTED = {
    'text': (models.EncryptedText, 'Über café ☕'),
    'char': (models.EncryptedChar, 'one'),
    'email': (models.EncryptedEmail, 'ada@example.com'),
    'int': (models.EncryptedInt, -42),
    'date': (models.EncryptedDate, date(2015, 2, 5)),
    'datetime': (
        models.EncryptedDateTime, datetime(2015, 2, 5, 15, 30, 1, 123456)),
    'binary': (models.EncryptedBinary, b'\x00\xffraw'),
}

RELEASED_TOKENS = [
    (kind, token)
    for tokens in (DJANGO_FERNET_FIELDS_0_6, DJFERNET_0_8_1)
    for kind, token in tokens.items()
]


def _insert(model, token):
    with connection.cursor() as cur:
        cur.execute(
            'INSERT INTO %s (value) VALUES (%%s)' % model._meta.db_table,
            [connection.Database.Binary(token)],
        )


def test_derived_key_matches_released_libraries():
    assert fields.EncryptedTextField().fernet_keys == [DERIVED_KEY]


@pytest.mark.parametrize('kind,token', RELEASED_TOKENS)
def test_reads_data_written_by_released_libraries(db, kind, token):
    model, expected = EXPECTED[kind]
    _insert(model, token)

    assert model.objects.get().value == expected


@pytest.mark.parametrize('kind,token', RELEASED_TOKENS)
def test_rewrites_data_after_reading_it(db, kind, token):
    model, expected = EXPECTED[kind]
    _insert(model, token)
    obj = model.objects.get()
    obj.save()

    assert model.objects.get().value == expected


@pytest.mark.parametrize('kind', sorted(DJFERNET_0_8_1))
def test_old_key_still_decrypts_after_rotation(db, kind):
    """FERNET_KEYS = [new, old]: old data reads, new data uses the new key."""
    model, expected = EXPECTED[kind]
    field_class = type(model._meta.get_field('value'))
    with override_settings(FERNET_KEYS=['rotated-in-2026', 'secret']):
        field = field_class()
        value = field.from_db_value(DJFERNET_0_8_1[kind], None, connection)
        token = field.fernet.encrypt(b'written after rotation')

    assert value == expected
    assert field.fernet_keys[1] == DERIVED_KEY
    with pytest.raises(fields.DecryptionError):
        field_class().from_db_value(token, None, connection)


@pytest.mark.parametrize('kind', sorted(DJFERNET_0_8_1_DJFERNET_PREFIX))
def test_djfernet_prefix_reads_pre_0_8_data(kind):
    model, expected = EXPECTED[kind]
    field_class = type(model._meta.get_field('value'))
    token = DJFERNET_0_8_1_DJFERNET_PREFIX[kind]
    try:
        # hkdf reads DJFERNET_PREFIX when imported, as it always has.
        with override_settings(DJFERNET_PREFIX=b'djfernet'):
            importlib.reload(hkdf)
            field = field_class()
            value = field.from_db_value(token, None, connection)
    finally:
        importlib.reload(hkdf)

    assert field.fernet_keys == [DERIVED_KEY_DJFERNET_PREFIX]
    assert value == expected
    with pytest.raises(fields.DecryptionError):
        field_class().from_db_value(token, None, connection)


def test_utils_force_text_from_djfernet_0_8_1():
    from fernet_fields.utils import force_text

    assert force_text(b'caf\xc3\xa9') == 'café'
