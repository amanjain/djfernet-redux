# Contributing

Thanks for your interest in contributing! The advice below will help you get your issue
fixed or pull request merged.

Please file bugs and send pull requests to the
[GitHub repository](https://github.com/amanjain/djfernet-redux) and
[issue tracker](https://github.com/amanjain/djfernet-redux/issues).
Report security issues privately instead, as described in [SECURITY.md](SECURITY.md).

## Submitting issues

Issues are easier to reproduce and resolve when they have:

- A pull request with a failing test demonstrating the issue
- A code example that produces the issue consistently
- A traceback (when applicable)

## Pull requests

When creating a pull request:

- Write tests (see below)
- Note user-facing changes in [CHANGES.md](CHANGES.md)
- Update the [README](README.md) as needed
- Add yourself to [AUTHORS.md](AUTHORS.md)

## Testing

Please add tests for any changes you submit. The tests should fail before your code
changes, and pass with your changes. Existing tests should not break.

Tests run with [tox](https://tox.wiki/) and [uv](https://docs.astral.sh/uv/), which
installs every Python version needed:

```sh
uvx --with tox-uv tox -e py314-django61-sqlite   # one environment
uvx --with tox-uv tox -l                         # list all environments
uvx --with tox-uv tox                            # the full matrix
```

The `pg` (psycopg2) and `pg3` (psycopg 3) environments need a PostgreSQL server and a
user that can create databases; the tests create and drop a database named `djftest`.
They connect to `localhost:5432` as `postgres` / `postgres` unless
`DJFERNET_TEST_PG_HOST`, `DJFERNET_TEST_PG_PORT`, `DJFERNET_TEST_PG_USER` or
`DJFERNET_TEST_PG_PASSWORD` say otherwise:

```sh
docker run -d --name djftest-pg -p 5432:5432 -e POSTGRES_PASSWORD=postgres postgres:18
```

`make test` runs the full matrix and writes a coverage report to `htmlcov/`.
