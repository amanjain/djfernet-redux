# Changelog

## Unreleased

- Add opt-in searchable encrypted email using a separate HMAC equality column, normalized uniqueness and synchronized instance/bulk writes.

## 1.0.0 (djfernet-redux)

First release as `djfernet-redux`, a drop-in replacement for djfernet 0.8.1
and django-fernet-fields: same `fernet_fields` module, settings and data
format. Tests decrypt data written by the released django-fernet-fields 0.6 and
djfernet 0.8.1.

### Fixed

- psycopg 3: saving any encrypted integer field raised
  `KeyError: 'BinaryField'` on Django 4.2+. Thanks to [Sid Mitra (Airbase)](https://github.com/Airbase) for
  the first fix; this one also covers custom `EncryptedField` integer
  subclasses.
- `EncryptedBinaryField` on PostgreSQL encrypted the driver's text
  representation of the bytes instead of the bytes. New writes store the bytes;
  see the [README](README.md#troubleshooting) for values written by djfernet 0.8.
- `derive_fernet_key` docstring said "32-bit" for a 32-byte key. Thanks to
  @intgr
  ([django-fernet-fields #37](https://github.com/orcasgit/django-fernet-fields/pull/37)).

### Added

- `EncryptedJSONField` for any JSON-serializable value, with `encoder` and
  `decoder` like Django's `JSONField`. Requested by @lucas-bremond
  ([django-fernet-fields #26](https://github.com/orcasgit/django-fernet-fields/issues/26)) and proposed by @Sult ([djfernet #1](https://github.com/yourlabs/djfernet/pull/1)).
- `DecryptionError`, raised with the field name and what to check when a
  stored value doesn't decrypt. It subclasses `InvalidToken`, so existing
  handlers keep working. Requested by @jpic ([djfernet GitLab #1](https://yourlabs.io/oss/djfernet/-/issues/1)).
- `fernet_fields.utils.force_text` restored: it was public in djfernet 0.8.1.

### Supported versions

- Includes djfernet's unreleased 0.9.0 work by @irtazaakram: support for newer
  Django and Python versions, and CI on GitHub Actions. Unlike that work,
  Django 2.2, 3.0 and 3.1 stay supported.
- Python 3.8 – 3.14, Django 2.2 – 6.1 (every Python each Django supports),
  PostgreSQL 9.6 – 18 with psycopg2 and psycopg 3, SQLite.
- Dependencies declared: `Django>=2.2` and `cryptography>=3.1`, the oldest
  versions tested (djfernet 0.8.1 declared neither).

### Packaging

- Published as `djfernet-redux` from <https://github.com/amanjain/djfernet-redux>.
- `pyproject.toml` replaces `setup.py` and setupmeta; the license metadata
  now says BSD-3-Clause, matching `LICENSE.txt` (djfernet 0.8.1 said MIT).
- README, changelog, contributing guide and authors are Markdown; the README holds
  the full documentation, replacing the Sphinx `doc/` folder.

## 0.8.1

- Don't convert binary to text

## 0.8.0

Switched back to django-fernet-fields for default salt, making it incompatible
with 0.7.4! But, compatible with django-fernet-fields, so that you can migrate
easily if you haven't already.

If, unfortunnately, you have already deployed this in production, you have two
options:

- re-encrypt your data to use django-fernet-fields instead of djfernet,
- or set settings.DJFERNET_PREFIX=djfernet to keep going

Sorry about this laborious releases.

Also, added EncryptedBinaryField.

## 0.7.4

First release since fork. Unfortunnately, my sed
s/django-fernet-fields/djfernet/ caused a change in the salt, make it
impossible to decrypt existing data!!

Added settings.DJFERNET_PREFIX to set it to django-fernet-fields and make it
compatible again through a setting.

Thanks to @sevdog for the report.

## 0.6 (2019.05.10)

- Support Postgres 10
- Drop support for Django < 1.11, Python 3.3/3.4
- Add support for Django 1.11 through 2.2, Python 3.7

## 0.5 (2017.02.22)

- Support Django 1.10.

## 0.4 (2015.09.18)

- Add `isnull` lookup.

## 0.3 (2015.05.29)

- Remove DualField and HashField. The only cases where they are useful, they
  aren't secure.

## 0.2.1 (2015.05.28)

- Fix issue getting IntegerField validators.

## 0.2 (2015.05.28)

- Extract HashField for advanced lookup needs.

## 0.1 (2015.05.27)

- Initial working version.
