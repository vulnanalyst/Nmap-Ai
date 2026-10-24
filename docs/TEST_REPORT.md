# Verification report

## Checks run

| Check | Result |
|---|---|
| `.venv/bin/pytest -q` | 25 passed |
| `cd frontend && npm run build` | Passed; TypeScript check and Vite production build completed |
| `cd frontend && npm run lint` | Passed with 9 React hook/fast-refresh warnings; no lint errors |
| `GET /api/v1/health` on the running local API | HTTP 200, `{"status":"ok","version":"1.0.0"}` |
| Frontend development server | Returned the Vite-served application HTML |

The test suite covers target authorization and scan execution boundaries, Nmap XML parsing and import limits, cancellation, legacy demo-record exclusion, traffic framing and classification input validation, findings and reports, API authentication, and model training/inference. Scan execution tests use controlled test doubles; no external network scan was launched for this report.

## Warnings and limits

- Pytest reports upstream Starlette/httpx and pandas deprecation warnings, plus a scikit-learn feature-name warning in the inference test.
- Oxlint reports React effect/fast-refresh warnings in existing data-loading and context patterns. The lint command exits successfully.
- The running API health check establishes process readiness only; it does not verify Nmap availability or database readiness. Nmap availability is reported separately by Settings.
