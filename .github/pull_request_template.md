## Summary
What this changes and why.

## Changes
-

## Testing
- [ ] Unit tests pass for the touched services (`python -m pytest tests`), and `npm run build` succeeds
- [ ] Login automation changes: real run against LoginLab, and **Verify** passes on the `.side`
- [ ] Endpoint changes: auth + owner-or-admin check, with a cross-user test
- [ ] Anything I could not run is listed here:

## Database
- [ ] No migration
- [ ] New migration in `backend/authrecon/backend/alembic/versions/` (runs at worker start); tested on a fresh `./install.sh`

## Configuration
- [ ] No new environment variables
- [ ] New variables are added to `install.sh` and the root `.env.example` where they apply:

## Checklist
- [ ] No credentials, cookies, tokens, real hostnames or personal data in code, tests, logs or screenshots
- [ ] Docs updated (README / ADMIN_GUIDE / SECURITY) if behaviour changed
