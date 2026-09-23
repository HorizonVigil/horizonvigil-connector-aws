# AWS Connector Release Runbook

## Production deployment

1. Merge only after `Build and Test`, `Integration & Isolation Tests`, and
   `Security Checks` pass.
2. The Google Cloud Build GitHub trigger builds `origin/main`, pushes
   `connector-aws:latest`, and deploys `connector-aws` in `us-central1`.
3. Confirm Cloud Run sends 100% traffic to the new ready revision.
4. Verify `GET /` returns `200` and `GET /api/v1/aws/evidence` without a bearer
   token returns the application-level `401 unauthenticated` response.
5. Run the signed-in frontend smoke suite and verify the Intelligence evidence
   view reports AWS evidence without an application error boundary.

Cloud Build intentionally omits `--set-env-vars`, preserving the service's
managed production environment. Runtime secrets must be changed through the
approved Cloud Run/Secret Manager configuration path, never through a second
deployment workflow.

## Rollback

Rollback when the health endpoint fails, authenticated evidence requests fail,
tenant isolation fails, or collection error rates materially exceed the prior
revision.

```sh
gcloud run services update-traffic connector-aws \
  --project cloudops360 \
  --region us-central1 \
  --to-revisions PREVIOUS_READY_REVISION=100
```

After rollback, verify the root health endpoint, the protected evidence route,
and one signed-in AWS evidence view. Preserve the failed revision and Cloud
Build logs for diagnosis.
