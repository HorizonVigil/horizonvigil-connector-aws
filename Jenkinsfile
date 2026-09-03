// HorizonVigil CI/CD — self-hosted Jenkins (e2-micro, us-west1).
// test -> build image -> push to Artifact Registry -> deploy to Cloud Run.
// `main` only for build/deploy; every push runs Test. SCM-polled every 2 min
// (Jenkins is IAP-only, so no inbound webhook). Build status is posted back
// to the GitHub commit via the API.
//
// Jenkins prerequisites (auto-provisioned by init.groovy.d):
//   - Plugins: workflow-aggregator, docker-workflow, git, credentials-binding
//   - Credential (Secret text) id `gh-pat` = GitHub token with `repo` scope
//   - The VM's attached service account can deploy to Cloud Run + push images

def SERVICE   = 'connector-aws'
def GH_REPO   = 'HorizonVigil/horizonvigil-connector-aws'
def PROJECT   = 'cloudops360'
def REGION    = 'us-central1'
def AR_HOST   = 'us-central1-docker.pkg.dev'
def IMAGE     = "us-central1-docker.pkg.dev/cloudops360/cloud-run-source-deploy/${SERVICE}"

/** Post a commit status to GitHub (best-effort — never fails the build). */
def ghStatus(String repo, String state, String desc) {
  withCredentials([string(credentialsId: 'gh-pat', variable: 'GH_PAT')]) {
    sh label: "github status: ${state}", script: """
      set +e
      SHA=\$(git rev-parse HEAD)
      curl -s -o /dev/null -X POST \
        -H "Authorization: token \$GH_PAT" -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${repo}/statuses/\$SHA" \
        -d '{"state":"${state}","context":"jenkins/ci","description":"${desc}","target_url":"'"\${BUILD_URL}"'"}'
      true
    """
  }
}

pipeline {
  agent any
  options {
    timeout(time: 25, unit: 'MINUTES')
    disableConcurrentBuilds()
    buildDiscarder(logRotator(numToKeepStr: '15'))
  }
  triggers { pollSCM('H/2 * * * *') }

  stages {
    stage('GitHub: pending') {
      steps { ghStatus(GH_REPO, 'pending', 'Jenkins build started') }
    }

    stage('Test') {
      agent { docker { image 'node:22-slim'; reuseNode true; args '-u root:root' } }
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

            printf '%s' "\$GH_PAT" > /tmp/gh_pat.\$\$
            docker build --secret id=gh_pat,src=/tmp/gh_pat.\$\$ -t "${IMAGE}:\$TAG" -t "${IMAGE}:latest" .
            rm -f /tmp/gh_pat.\$\$

            TOKEN=\$(curl -s -H 'Metadata-Flavor: Google' \
              'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
              | sed -n 's/.*"access_token":"\\([^"]*\\)".*/\\1/p')
            echo "\$TOKEN" | docker login -u oauth2accesstoken --password-stdin https://${AR_HOST}
            docker push "${IMAGE}:\$TAG"
            docker push "${IMAGE}:latest"

            docker run --rm google/cloud-sdk:slim gcloud run deploy ${SERVICE} \
              --image="${IMAGE}:\$TAG" --project=${PROJECT} --region=${REGION} \
              --platform=managed --min-instances=0 --max-instances=1 --quiet
          """
        }
      }
    }
  }

  post {
    success { ghStatus(GH_REPO, 'success', 'Jenkins: tests + deploy passed') }
    unstable { ghStatus(GH_REPO, 'failure', 'Jenkins: unstable') }
    failure { ghStatus(GH_REPO, 'failure', 'Jenkins build failed') }
    always  { sh 'docker image prune -f >/dev/null 2>&1 || true' }
  }
}
