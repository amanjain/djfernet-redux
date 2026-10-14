# djfernet-redux

[Fernet](https://cryptography.io/en/latest/fernet/) symmetric encryption for Django
model fields, using the [cryptography](https://cryptography.io/en/latest/) library.
A maintained continuation of [djfernet](https://github.com/yourlabs/djfernet), itself
a fork of [django-fernet-fields](https://github.com/orcasgit/django-fernet-fields).

**Drop-in replacement** for `djfernet` and `django-fernet-fields`: the same import
name (`fernet_fields`), the same settings and the same encrypted data format. Swap the
package and nothing else changes: no code, migration or data changes.

```sh
pip uninstall djfernet django-fernet-fields
pip install djfernet-redux
```

Uninstall the old package first: both install the `fernet_fields` module.

## Supported versions

Every combination below is tested.

| | |
|---|---|
| Python | 3.8 – 3.14 |
| Django | 2.2 – 6.1, each on the Python versions it supports |
| Databases | PostgreSQL 9.6 – 18 (psycopg2, and psycopg 3 from Django 4.2), SQLite |
| cryptography | 3.1 and later |

Other Django database backends with `BinaryField` support (MySQL, MariaDB, Oracle)
should work but are not tested.

## Usage

Import and use the field classes in your models:

```python
from django.db import models
from fernet_fields import EncryptedTextField


class Customer(models.Model):
    tax_id = EncryptedTextField()
```

Read and write `tax_id` as usual: values are encrypted before they are sent to the
database and decrypted when read. Encryption happens in your app; the key never
reaches the database server, which only ever sees the encrypted value.

### Field types

`EncryptedTextField`, `EncryptedCharField`, `EncryptedEmailField`,
`EncryptedIntegerField`, `EncryptedDateField`, `EncryptedDateTimeField`,
`EncryptedBinaryField` and `EncryptedJSONField`. Each accepts the same arguments as
its unencrypted Django counterpart.

`EncryptedJSONField` stores any JSON-serializable value (dicts, lists, strings,
numbers, booleans). Like Django's `JSONField` it accepts `encoder` and `decoder`, for
example `encoder=DjangoJSONEncoder` to store `Decimal` and `datetime` values (they read
back as strings). Its form field, used by the admin and `ModelForm`, needs Django 3.1
or later.

To encrypt another field class, inherit from `EncryptedField` and that class:

```python
from django.db import models
from fernet_fields import EncryptedField


class EncryptedBigIntegerField(EncryptedField, models.BigIntegerField):
    pass
```

### Nullable fields

A nullable encrypted field stores Python `None` as SQL `NULL`, which shows anyone with
database access whether a value is present. If that matters, use a non-nullable field
and store an "empty" sentinel value, which is encrypted like any other value.

## Keys

By default the fields use your `SECRET_KEY` setting as the encryption key.

To use dedicated keys, list them in `FERNET_KEYS`. The first key encrypts all new data;
decryption tries every key in order. To rotate keys, put the new key first and keep the
old ones until all data has been re-saved:

```python
FERNET_KEYS = [
    env("FERNET_KEY"),       # encrypts new and changed data
    env("FERNET_KEY_2025"),  # still decrypts older data
]
```

> [!WARNING]
> Keep every key that has encrypted data. If a key is lost, the data encrypted with it
> is lost too. Anyone with the key can read the data.

### Disabling HKDF

Fernet needs a 32-byte, url-safe base64-encoded key. By default the fields derive one
from each configured key with
[HKDF](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#cryptography.hazmat.primitives.kdf.hkdf.HKDF),
so any string works as a key.

To provide Fernet keys directly (for example from
[`Fernet.generate_key()`](https://cryptography.io/en/latest/fernet/#cryptography.fernet.Fernet.generate_key)),
set `FERNET_USE_HKDF = False`. Every key in `FERNET_KEYS` must then be a valid Fernet
key; an invalid key usually fails with an "incorrect padding" error. Without
`FERNET_KEYS`, `SECRET_KEY` itself must be a Fernet key.

### Data from djfernet 0.7

djfernet 0.7.x derived keys with a different HKDF salt. If your data was written by
djfernet before 0.8, add this setting (note the bytestring):

```python
DJFERNET_PREFIX = b'djfernet'
```

Data written by django-fernet-fields or djfernet 0.8 and later needs no setting.

## Lookups, indexes and ordering

Fernet encryption is not deterministic: the same value encrypts differently every time.
Filtering, indexing or enforcing uniqueness on encrypted data can't work, so:

- `primary_key=True`, `unique=True` and `db_index=True` raise `ImproperlyConfigured`.
- Every lookup except `isnull` raises `FieldError`.
- Ordering by an encrypted field doesn't raise, but it orders by the encrypted bytes,
  which is meaningless.

The admin and forms show decrypted values, so restrict admin access and `list_display`
accordingly.

## Auditing existing data

A normal ORM scan stops at the first unreadable encrypted value. To inspect the
selected rows without modifying them or returning their private contents:

```python
from fernet_fields.audit import audit_encrypted_fields

for failure in audit_encrypted_fields(Customer.objects.all(), batch_size=500):
    print(failure.model, failure.pk, failure.field, failure.reason)
```

Pass `fields=["tax_id"]` to limit the fields inspected. Queryset filtering and the
database alias are preserved. Each result contains only the model label, primary
key, field name and a reason: `cannot-decrypt`, `invalid-storage` or `invalid-value`.
Treat identifiers in audit reports as sensitive and restrict access to them.

`cannot-decrypt` does not distinguish an incorrect key from damaged ciphertext.
The audit cannot recover lost keys, repair corrupted data or infer that a column
should be treated as plaintext. It ignores SQL `NULL` values. Database driver and
query errors still propagate; they are not reported as individual data failures.

## Migrations

The database can't encrypt existing values, so `AlterField` from a plain field to an
encrypted one doesn't work. Instead:

1. Add the encrypted field under a new name, with `null=True`.
2. Copy the values in a data migration (`RunPython` with the ORM, not raw SQL); saving
   through the ORM encrypts them.
3. Remove the old field and, if needed, rename the new one.

## Troubleshooting

**`DecryptionError: Can't decrypt <field>`**

Text-encoded Fernet tokens returned by a legacy text column are accepted, including
PostgreSQL's `\\x` hexadecimal bytea representation, as are bytes and database
buffer values. This does not encrypt plaintext or repair a
wrongly typed column. Invalid inputs raise the same field-specific error without
including their contents.

A stored value doesn't decrypt with any configured key. Check that `FERNET_KEYS` (or
`SECRET_KEY`) still includes the key the data was written with, `FERNET_USE_HKDF`, and
`DJFERNET_PREFIX` for data from djfernet 0.7. It also happens when the column holds
unencrypted or empty values, for example after an `AlterField` from a plain field.
`DecryptionError` subclasses `cryptography.fernet.InvalidToken`, so existing
`except InvalidToken` handlers keep working.

**`EncryptedDateTimeField` returns naive datetimes with `USE_TZ = True`**

On SQLite (and other backends without native time zone support) aware datetimes are
stored in UTC and read back as naive UTC values; on PostgreSQL they read back aware.
Use `timezone.make_aware(value, timezone.utc)` where you need an aware value. This is
unchanged from django-fernet-fields, so existing code keeps working.

**`EncryptedBinaryField` values written on PostgreSQL by djfernet 0.8**

djfernet 0.8 encrypted the database driver's text representation of the bytes instead
of the bytes themselves, so those values read back as text such as
`'\\000\\377'::bytea` (psycopg2) or `Binary(b'...')` (psycopg 3, cut short for longer
values). djfernet-redux encrypts the bytes themselves; re-save affected values from
their original source.

## Credits

djfernet-redux continues the work of the people who built and maintained this library,
and all credit for its design and code belongs to them:

- [django-fernet-fields](https://github.com/orcasgit/django-fernet-fields), the
  original library, © 2015 [ORCAS, Inc.](https://github.com/orcasgit), created by
  [Carl Meyer](https://github.com/carljm) with
  [Jess Johnson](https://github.com/grokcode) and maintained by Brad Pitcher, with
  contributions from Alex Riina, Vlad Temian, Yacht Shaver, Owen Miller, Douglas
  Anderson, Carel Burger and Brian Helba.
- [djfernet](https://github.com/yourlabs/djfernet), the maintained fork by
  [James Pic](https://github.com/jpic) (yourlabs), with contributions from
  [Stefan](https://github.com/stefan6419846),
  [irtazaakram](https://github.com/irtazaakram) and Flávio Juvenal da Silva Junior.

Fixes and ideas in djfernet-redux also come from Sid Mitra
([Airbase](https://github.com/Airbase)'s psycopg 3 fix),
[intgr](https://github.com/intgr), [lucas-bremond](https://github.com/lucas-bremond)
and [Sult](https://github.com/Sult); see the
[changelog](https://github.com/amanjain/djfernet-redux/blob/main/CHANGES.md).

The original BSD license and copyright notice are kept in
[LICENSE.txt](https://github.com/amanjain/djfernet-redux/blob/main/LICENSE.txt), and
the original authors in
[AUTHORS.md](https://github.com/amanjain/djfernet-redux/blob/main/AUTHORS.md). The full
commit history of both projects is preserved in this repository.

## Contributing and help

- Source, issues and pull requests: <https://github.com/amanjain/djfernet-redux>
- How to run the tests:
  [CONTRIBUTING.md](https://github.com/amanjain/djfernet-redux/blob/main/CONTRIBUTING.md)
- What changed in each release:
  [CHANGES.md](https://github.com/amanjain/djfernet-redux/blob/main/CHANGES.md)
- Security issues: report privately, see
  [SECURITY.md](https://github.com/amanjain/djfernet-redux/blob/main/SECURITY.md)
- Install from [PyPI](https://pypi.org/project/djfernet-redux/):
  `pip install djfernet-redux`
