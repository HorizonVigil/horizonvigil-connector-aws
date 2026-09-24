# HorizonVigil AWS Connector

Production AWS collection and evidence service for HorizonVigil. It owns AWS
connection validation, discovery, capability health, collection lineage and the
tenant-scoped evidence contract consumed by Horizon Intelligence.

## Release path

- Pull requests run build, typecheck, unit, integration, isolation, dependency,
  secret and container-security checks in GitHub Actions.
- A push to `main` triggers the connected Google Cloud Build pipeline in
  `cloudbuild.yaml`. Cloud Build is the only production deployment writer.
- The separate GitHub production deployment job was removed because it
  duplicated Cloud Build and could replace the Cloud Run environment with
  missing secrets.
- Pushes to `test` retain the isolated test-project deployment path.

See [RELEASE.md](RELEASE.md) for deployment verification and rollback.

## Local validation

```sh
npm install
npm run typecheck
npm run build
npm test
```

Integration tests additionally require `INTEGRATION_SUPABASE_URL` and
`INTEGRATION_SUPABASE_ANON_KEY`.
