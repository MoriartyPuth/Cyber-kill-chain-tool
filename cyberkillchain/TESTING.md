# Testing Guide

## Local Commands

Run all tests:

```bash
python -m unittest discover -s tests -v
```

Run import smoke check:

```bash
python -B -c "import app; print('import_ok')"
```

Run app startup smoke check (manual stop with Ctrl+C):

```bash
python app.py
```

## Notes

- Tests are written with Python `unittest` and avoid external test plugins.
- Route smoke tests use Flask test client and expect unauthenticated redirects where applicable.
