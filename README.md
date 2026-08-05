# cloudops-connector-aws

Skeleton deploy — deployed and live on Cloud Run, but business logic has not
been ported yet. `GET /` returns a status identity check only.

Will be ported from `services/aws-accounts-api/` in the original `cloudops360-1` monorepo.

## Deployment

GitHub Actions on push to `main` — builds the container, pushes to Artifact
Registry, deploys to Cloud Run. See `.github/workflows/deploy.yml`.
