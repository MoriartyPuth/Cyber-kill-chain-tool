## Summary

- What changed:
- Why:

## Validation

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -B -c "import app; print('import_ok')"`
- [ ] Manual route smoke for critical pages

## Refactor Guard Checklist

- [ ] Updated dependency container (`dependencies.py`) for any new route/service dependency
- [ ] Added/updated tests for new service logic
- [ ] Confirmed route registrations still resolve and endpoints are reachable
- [ ] Verified no stale legacy imports/usages remain
