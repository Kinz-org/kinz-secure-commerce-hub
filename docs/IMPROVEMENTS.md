# Improvements backlog

Open items found by reading the code, highest priority first. Each one says what is
wrong, why it matters and how to check the fix. Tick an item `[x] … (done YYYY-MM-DD)`
in the PR that fixes it.

- [x] **`JWT_ALGORITHM` accepted RS256/RS384/RS512 that can never work.** (done 2026-10-12)
  `Settings._validate_jwt_alg` (`src/api/utils/config.py`) allowed RS*, but
  `jwt_handler.issue_token`/`verify_token` sign and verify with `JWT_SECRET`, a shared
  string and not a PEM key pair. An RS* setting passed startup validation, then every
  `/api/v1/auth/login` failed at signing time. Check: `Settings(JWT_ALGORITHM="RS256")` raises;
  `tests/backend/test_security_hardening.py::test_jwt_asymmetric_algorithm_rejected_at_startup`.

- [ ] **`DEMO_USER_ROLE` is not validated.** `Settings.DEMO_USER_ROLE` is a free string,
  but `rbac.current_user` rejects any token whose `role` is not `viewer`/`analyst`/`admin`.
  A typo such as `DEMO_USER_ROLE=Admin` lets the demo user log in successfully and then
  get 401 on every protected route, with nothing at startup pointing at the cause.
  Fix: a `field_validator` restricting it to the three roles in `rbac.Role`. Check: a
  test that `Settings(DEMO_USER_ROLE="Admin")` raises.

- [ ] **KPI endpoints crash with 500 on one unparsable product cost.** `kpis.summary` and
  `kpis.channels` (`src/api/routes/kpis.py`) both do `float(row["cost_tnd"])` for every row
  of `data/raw/products.csv`, so a single blank or malformed cost raises `ValueError` and
  takes down both endpoints. The ETL (`run_etl.transform_products`) already coerces and
  drops such rows, so the API is stricter than the pipeline feeding the same data. The
  product-cost loading is also duplicated verbatim in both handlers. Fix: one shared
  loader that skips (and logs) unparsable costs. Check: a test with a blank `cost_tnd`
  row that expects 200 from `/api/v1/kpis/summary` and `/api/v1/kpis/channels`.

- [ ] **`transform_products` raises a bare `KeyError` when `stock_units` is missing.**
  `run_etl.transform_products` validates a `required` column set that omits
  `stock_units`, then reads `df["stock_units"]` unconditionally. A products export without
  that column fails with `KeyError: 'stock_units'` instead of the clear
  `ValueError("products.csv missing columns: …")` the function is written to give. Fix:
  add `stock_units` to `required` (or default it to 0 when absent, if that is the intent).
  Check: a test passing a frame without `stock_units`.

- [ ] **`run_etl.load` stamps `ran_at` with deprecated, naive `datetime.utcnow()`.**
  It emits a `DeprecationWarning` on Python 3.12 (one of the two CI versions) and yields
  a timestamp with no timezone, unlike `audit.py` and `jwt_handler.py`, which already use
  `datetime.now(UTC)`. Fix: use `datetime.now(UTC).isoformat()`. Check: a test that
  `load(...)["ran_at"]` parses with a `+00:00` offset.
