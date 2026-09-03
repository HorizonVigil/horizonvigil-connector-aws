// HorizonVigil CI/CD — runs on the self-hosted Jenkins (e2-micro, us-west1).
// Mirrors .github/workflows/deploy.yml: test -> build image -> push to
// Artifact Registry -> deploy to Cloud Run. `main` only for build/deploy;
// every branch/PR runs Test.
//
// Jenkins prerequisites (see JENKINS-SETUP.md in the ops notes):
//   - Plugins: Docker Pipeline, Pipeline: GitHub, Credentials Binding
//   - Credential (Secret text) id `gh-pat` = a GitHub PAT (scope: repo) for
//     the HorizonVigil org — clones the private cloudops-shared-lib.
//   - The Jenkins VM's attached service account can deploy to Cloud Run +
//     push to Artifact Registry (roles/editor, or the scoped set).

def SERVICE = 'connector-aws'
def PROJECT = 'cloudops360'
def REGION  = 'us-central1'
def AR_HOST = 'us-central1-docker.pkg.dev'
def REPO    = 'cloud-run-source-deploy'

pipeline {
  agent any
  options {
    timeout(time: 25, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '15'))
  }
  triggers { pollSCM('H/2 * * * *') }  // no inbound webhook needed (Jenkins is IAP-only)

  environment {
    IMAGE = "${AR_HOST}/${PROJECT}/${REPO}/${SERVICE}"
  }

  stages {
    stage('Test') {
      agent {
        docker { image 'node:22-slim'; reuseNode true; args '-u root:root' }
      }
      steps {
        withCredentials([string(credentialsId: 'gh-pat', variable: 'GH_PAT')]) {
          sh '''
            set -e
            apt-get update >/dev/null && apt-get install -y git >/dev/null
            git config --global url."https://x-access-token:${GH_PAT}@github.com/".insteadOf "ssh://git@github.com/"
            git config --global url."https://x-access-token:${GH_PAT}@github.com/".insteadOf "https://github.com/"
            npm ci
            npm run typecheck
            npm test
            npm run build
          '''
        }
      }
    }

    stage('Build, push & deploy') {
      when { branch 'main' }
      steps {
        withCredentials([string(credentialsId: 'gh-pat', variable: 'GH_PAT')]) {
          sh """
            set -e
            export DOCKER_BUILDKIT=1
            TAG=\$(git rev-parse --short HEAD)

            printf '%s' "\$GH_PAT" > /tmp/gh_pat
            docker build --secret id=gh_pat,src=/tmp/gh_pat -t "\$IMAGE:\$TAG" -t "\$IMAGE:latest" .
            rm -f /tmp/gh_pat

            # Auth to Artifact Registry with the VM service account (metadata server).
            TOKEN=\$(curl -s -H 'Metadata-Flavor: Google' \
              'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
              | sed -n 's/.*"access_token":"\\([^"]*\\)".*/\\1/p')
            echo "\$TOKEN" | docker login -u oauth2accesstoken --password-stdin https://${AR_HOST}
            docker push "\$IMAGE:\$TAG"
            docker push "\$IMAGE:latest"

            # Deploy via the cloud-sdk container (also auto-auths via metadata).
            docker run --rm google/cloud-sdk:slim gcloud run deploy ${SERVICE} \
              --image="\$IMAGE:\$TAG" --project=${PROJECT} --region=${REGION} \
              --platform=managed --min-instances=0 --max-instances=1 --quiet
          """
        }
      }
    }
  }

  post {
    always  { sh 'docker image prune -f >/dev/null 2>&1 || true' }
    success { echo "Deployed ${SERVICE}" }
    failure { echo "FAILED ${SERVICE} @ ${env.GIT_COMMIT}" }
  }
}
