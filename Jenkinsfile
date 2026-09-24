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

    // The build + push + deploy is offloaded to Google Cloud Build (free
    // 120 build-min/day) via the repo's own cloudbuild.yaml. Doing the
    // multi-stage `docker build` locally starves the 1 GB e2-micro and the
    // durable `sh` task drops out ("agent seems to be offline"). Cloud Build
    // also uses the `gh_pat` Secret Manager secret for the private shared-lib
    // clone — that secret must have read access to
    // github.com/kknr8367/cloudops-shared-lib (see JENKINS-SETUP.md).
    stage('Build, push & deploy') {
      agent { docker { image 'google/cloud-sdk:slim'; reuseNode true; args '-u root:root' } }
      steps {
        sh """
          set -e
          gcloud builds submit --project=${PROJECT} --region=${REGION} \
            --config=cloudbuild.yaml --gcs-log-dir=gs://${PROJECT}_cloudbuild/logs .
        """
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
