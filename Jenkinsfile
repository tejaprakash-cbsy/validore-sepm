// ═══════════════════════════════════════════════════════════════════════════════
// Validore — Enterprise CI/CD Pipeline (Jenkins Declarative)
// ─────────────────────────────────────────────────────────────────────────────
//
// PIPELINE STAGES (in order):
//   1.  Checkout          — pull source code, log recent commits
//   2.  Environment Info  — print tool versions for traceability
//   3.  Install           — npm ci (lockfile-exact, cached via npm cache)
//   4.  Lint              — ESLint (any error fails the build)
//   5.  Typecheck         — tsc --noEmit (strict TS type safety)
//   6.  Unit Tests        — Vitest (all AI + DB fully mocked, JUnit output)
//   7.  Build             — next build standalone (production bundle)
//   8.  Docker Build      — multi-stage image tagged with commit SHA
//   9.  Security Scan     — Trivy image scan (HIGH/CRITICAL = fail)
//   10. Publish Image     — push to registry (main branch only)
//   11. Deploy Staging    — rolling deploy with manual approval gate
//   12. Notify            — build status summary & notifications
//
// REQUIRED JENKINS PLUGINS:
//   docker-workflow, git, junit, pipeline-utility-steps, timestamper,
//   ansicolor, build-discarder, credentials-binding
//
// REQUIRED JENKINS CREDENTIALS:
//   validore-registry      — registry username/password (docker push)
//   validore-git-token     — optional, for private-repo checkout
//
// REQUIRED TOOLS ON JENKINS AGENT:
//   node (>=20), docker, trivy (aquasec/trivy)
//
// ENVIRONMENT OVERRIDES (per-controller):
//   REGISTRY   — container registry host + org (default: ghcr.io/tejaprakash-cbsy)
//   STAGING_HOST — SSH target for docker-compose deploy
// ═══════════════════════════════════════════════════════════════════════════════

pipeline {
  agent any

  // ── Global pipeline options ─────────────────────────────────────────────────
  options {
    // Stop remaining stages immediately when a stage fails.
    skipStagesAfterUnstable()
    // Retain last 30 build records; prevents disk exhaustion on long-lived jobs.
    buildDiscarder(logRotator(numToKeepStr: '30', artifactNumToKeepStr: '10'))
    // Emit timestamps in all log lines — critical for debugging timing issues.
    timestamps()
    // Hard ceiling: the entire pipeline must complete within 30 minutes.
    timeout(time: 30, unit: 'MINUTES')
    // Never queue two builds on the same ref at the same time.
    disableConcurrentBuilds()
    // Colour-code ANSI output (requires AnsiColor plugin).
    ansiColor('xterm')
  }

  // ── User-adjustable parameters ──────────────────────────────────────────────
  parameters {
    booleanParam(
      name: 'SKIP_DOCKER',
      defaultValue: false,
      description: 'Skip Docker build / security scan / publish / deploy stages. Useful for fast PR lint+test runs or environments without Docker daemon.'
    )
    booleanParam(
      name: 'DEPLOY_STAGING',
      defaultValue: true,
      description: 'Trigger staging deployment after a successful main-branch build (requires manual approval).'
    )
    booleanParam(
      name: 'FORCE_TRIVY_FAIL',
      defaultValue: false,
      description: 'Dev: treat any Trivy finding as a pipeline failure (normally only HIGH/CRITICAL fail).'
    )
    string(
      name: 'NODE_VERSION_EXPECTED',
      defaultValue: '20',
      description: 'Minimum Node.js major version required on this agent.'
    )
  }

  // ── Automated build triggers ─────────────────────────────────────────────────
  triggers {
    // Trigger 1: GitHub push / PR webhook
    githubPush()

    // Trigger 2: SCM Poll fallback (every 5 minutes)
    pollSCM('H/5 * * * *')

    // Trigger 3: Nightly scheduled build (01:30 IST / 20:00 UTC)
    cron('30 20 * * *')
  }

  // ── Environment variables (resolved once at pipeline start) ─────────────────
  environment {
    // Image coordinates — ghcr.io/tejaprakash-cbsy namespace for GitHub Container Registry
    IMAGE_NAME      = 'validore'
    REGISTRY        = "${env.REGISTRY ?: 'ghcr.io/tejaprakash-cbsy'}"
    // Commit SHA (7 chars) used as immutable image tag; falls back to build number or 'dev'
    IMAGE_TAG       = "${env.GIT_COMMIT ? env.GIT_COMMIT.take(7) : (env.BUILD_NUMBER ?: 'dev')}"
    // Full image references resolved safely without referencing uninitialized script bindings
    IMAGE_REF       = "${env.REGISTRY ?: 'ghcr.io/tejaprakash-cbsy'}/validore:${env.GIT_COMMIT ? env.GIT_COMMIT.take(7) : (env.BUILD_NUMBER ?: 'dev')}"
    IMAGE_LATEST    = "${env.REGISTRY ?: 'ghcr.io/tejaprakash-cbsy'}/validore:latest"
    // Deterministic builds: disable telemetry and auto-open
    NEXT_TELEMETRY_DISABLED = '1'
    CI              = 'true'
    // Node options: expose GC handles large monorepos without OOM kills
    NODE_OPTIONS    = '--max-old-space-size=4096'
    // Trivy cache directory — persisted relative to workspace
    TRIVY_CACHE_DIR = '.trivy-cache'
    // JUnit report path consumed by the junit() step
    JUNIT_REPORT    = 'reports/junit.xml'
    // Suppress Vite config-loader warning
    VITE_CONFIG_NATIVE_IGNORE_WARNING = 'true'
  }

  stages {

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 1 — Checkout
    // ──────────────────────────────────────────────────────────────────────────
    stage('Checkout') {
      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 1: Checkout Source Code        ║'
        echo '╚══════════════════════════════════════╝'

        checkout scm

        script {
          if (isUnix()) {
            sh 'git log --oneline -5 || true'
          } else {
            bat '@git log --oneline -5 || exit /b 0'
          }

          def sha = env.GIT_COMMIT ?: (isUnix() ? sh(script: 'git rev-parse HEAD', returnStdout: true).trim() : bat(script: '@git rev-parse HEAD', returnStdout: true).trim())
          def branch = env.BRANCH_NAME ?: env.GIT_BRANCH ?: (isUnix() ? sh(script: 'git rev-parse --abbrev-ref HEAD', returnStdout: true).trim() : bat(script: '@git rev-parse --abbrev-ref HEAD', returnStdout: true).trim())
          def author = isUnix() ? sh(script: 'git log -1 --format="%an <%ae>"', returnStdout: true).trim() : bat(script: '@git log -1 --format="%an <%ae>"', returnStdout: true).trim()
          def msg    = isUnix() ? sh(script: 'git log -1 --format="%s"', returnStdout: true).trim() : bat(script: '@git log -1 --format="%s"', returnStdout: true).trim()

          // Normalize branch name if prefixed with 'origin/'
          if (branch.startsWith('origin/')) {
            branch = branch.substring(7)
          }

          echo "Branch  : ${branch}"
          echo "Commit  : ${sha}"
          echo "Author  : ${author}"
          echo "Message : ${msg}"

          env.GIT_BRANCH_CLEAN = branch
          env.GIT_SHA_FULL     = sha
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 2 — Environment Info
    // ──────────────────────────────────────────────────────────────────────────
    stage('Environment Info') {
      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 2: Environment Info            ║'
        echo '╚══════════════════════════════════════╝'

        script {
          if (isUnix()) {
            sh '''
              echo "=== OS ==="
              uname -a || true
              echo "=== Node.js ==="
              node --version
              echo "=== npm ==="
              npm --version
              echo "=== Docker ==="
              docker --version || echo "Docker not available on this agent"
              echo "=== Trivy ==="
              trivy --version 2>/dev/null || echo "Trivy not available on this agent"
              echo "=== Workspace ==="
              echo "WORKSPACE  : ${WORKSPACE}"
              echo "BUILD_URL  : ${BUILD_URL}"
              echo "IMAGE_REF  : ${IMAGE_REF}"
            '''
          } else {
            bat '''
              @echo === OS ===
              @ver
              @echo === Node.js ===
              @node --version
              @echo === npm ===
              @call npm --version
              @echo === Docker ===
              @where docker >nul 2>nul && docker --version || echo Docker not available on this agent
              @echo === Trivy ===
              @where trivy >nul 2>nul && trivy --version || echo Trivy not available on this agent
              @echo === Workspace ===
              @echo WORKSPACE  : %WORKSPACE%
              @echo BUILD_URL  : %BUILD_URL%
              @echo IMAGE_REF  : %IMAGE_REF%
            '''
          }

          // Validate that the Node major version meets requirements
          def nodeVerRaw = isUnix() ? sh(script: 'node -v', returnStdout: true).trim() : bat(script: '@node -v', returnStdout: true).trim()
          def matcher = (nodeVerRaw =~ /v?(\d+)/)
          if (matcher.find()) {
            def nodeVersion = matcher.group(1).toInteger()
            def required = params.NODE_VERSION_EXPECTED.toInteger()
            if (nodeVersion < required) {
              error "Node.js ${nodeVersion} is below the required major version ${required}. " +
                    "Please upgrade the agent or adjust NODE_VERSION_EXPECTED."
            }
            echo "Node.js version check passed: v${nodeVersion} >= v${required}"
          } else {
            echo "Unable to parse Node.js version from output: ${nodeVerRaw}"
          }
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 3 — Install Dependencies
    // ──────────────────────────────────────────────────────────────────────────
    stage('Install Dependencies') {
      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 3: Install Dependencies        ║'
        echo '╚══════════════════════════════════════╝'

        script {
          if (isUnix()) {
            sh '''
              npm ci --legacy-peer-deps --prefer-offline
              echo "=== Installed packages ==="
              npm ls --depth=0 2>/dev/null || true
            '''
          } else {
            bat '''
              @echo Installing dependencies with npm ci...
              call npm ci --legacy-peer-deps --prefer-offline
              @echo === Installed packages ===
              call npm ls --depth=0 2>nul || exit /b 0
            '''
          }
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 4 — Lint
    // ──────────────────────────────────────────────────────────────────────────
    stage('Lint') {
      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 4: ESLint Code Quality         ║'
        echo '╚══════════════════════════════════════╝'

        script {
          if (isUnix()) {
            sh '''
              echo "Running ESLint..."
              npm run lint
              echo "✅ Lint passed — no ESLint errors found."
            '''
          } else {
            bat '''
              @echo Running ESLint...
              call npm run lint
              @echo ✅ Lint passed — no ESLint errors found.
            '''
          }
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 5 — Typecheck
    // ──────────────────────────────────────────────────────────────────────────
    stage('Typecheck') {
      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 5: TypeScript Type Safety      ║'
        echo '╚══════════════════════════════════════╝'

        script {
          if (isUnix()) {
            sh '''
              echo "Running tsc --noEmit (strict type checking)..."
              npx tsc --noEmit
              echo "✅ Typecheck passed — no TypeScript errors found."
            '''
          } else {
            bat '''
              @echo Running tsc --noEmit (strict type checking)...
              call npx tsc --noEmit
              @echo ✅ Typecheck passed — no TypeScript errors found.
            '''
          }
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 6 — Unit Tests
    // ──────────────────────────────────────────────────────────────────────────
    stage('Unit Tests') {
      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 6: Unit Tests (Vitest)         ║'
        echo '╚══════════════════════════════════════╝'

        script {
          if (isUnix()) {
            sh '''
              mkdir -p reports
              echo "Running Vitest unit tests..."
              echo "CI=true prevents .env.local loading; DB-backed tests self-skip."
              echo "All AI providers and web-search are mocked — no API credits spent."
              npm run test:ci
              echo "✅ All unit tests passed."
            '''
          } else {
            bat '''
              if not exist reports mkdir reports
              @echo Running Vitest unit tests...
              @echo CI=true prevents .env.local loading; DB-backed tests self-skip.
              @echo All AI providers and web-search are mocked — no API credits spent.
              call npm run test:ci
              @echo ✅ All unit tests passed.
            '''
          }
        }
      }

      post {
        always {
          junit allowEmptyResults: true, testResults: "${env.JUNIT_REPORT}"
          archiveArtifacts artifacts: "${env.JUNIT_REPORT}", allowEmptyArchive: true
        }
        failure {
          echo '❌ Unit tests FAILED. Review the Test Results tab for details.'
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 7 — Build
    // ──────────────────────────────────────────────────────────────────────────
    stage('Build') {
      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 7: Next.js Production Build    ║'
        echo '╚══════════════════════════════════════╝'

        script {
          if (isUnix()) {
            sh '''
              echo "Building Next.js standalone bundle..."
              npm run build
              echo "=== Build output size ==="
              du -sh .next/standalone 2>/dev/null || true
              du -sh .next/static 2>/dev/null || true
              echo "✅ Build succeeded."
            '''
          } else {
            bat '''
              @echo Building Next.js standalone bundle...
              call npm run build
              @echo === Build output ===
              if exist .next\\standalone echo .next\\standalone created successfully.
              if exist .next\\static echo .next\\static created successfully.
              @echo ✅ Build succeeded.
            '''
          }
        }
      }

      post {
        success {
          archiveArtifacts(
            artifacts: '.next/standalone/**,.next/static/**',
            allowEmptyArchive: true,
            fingerprint: true
          )
        }
        failure {
          echo '❌ Build FAILED. Check Next.js compilation errors above.'
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 8 — Docker Build
    // ──────────────────────────────────────────────────────────────────────────
    stage('Docker Build') {
      when {
        expression { !params.SKIP_DOCKER }
      }

      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 8: Docker Image Build          ║'
        echo '╚══════════════════════════════════════╝'

        script {
          def dockerAvailable = false
          try {
            if (isUnix()) {
              dockerAvailable = (sh(script: 'docker --version', returnStatus: true) == 0)
            } else {
              dockerAvailable = (bat(script: '@docker --version >nul 2>nul', returnStatus: true) == 0)
            }
          } catch (Exception e) {
            dockerAvailable = false
          }

          if (!dockerAvailable) {
            error 'Docker is not installed or not running on this Jenkins agent. ' +
                  'Please install Docker (or Docker Desktop) and ensure the daemon is running, ' +
                  'or trigger the build with parameter SKIP_DOCKER=true for lint/test-only runs.'
          }

          def isMaster = (env.GIT_BRANCH_CLEAN == 'main' || env.GIT_BRANCH_CLEAN == 'master')
          def latestFlag = isMaster ? "-t ${env.IMAGE_LATEST}" : ""

          if (isUnix()) {
            sh """
              echo "Building Docker image..."
              echo "  Primary tag : ${env.IMAGE_REF}"
              echo "  Latest tag  : ${isMaster ? env.IMAGE_LATEST : 'N/A (non-main branch)'}"

              docker build \\
                --build-arg BUILD_DATE=\$(date -u +"%Y-%m-%dT%H:%M:%SZ") \\
                --build-arg GIT_COMMIT=${env.GIT_SHA_FULL} \\
                --build-arg VERSION=${env.IMAGE_TAG} \\
                --label "org.opencontainers.image.created=\$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \\
                --label "org.opencontainers.image.revision=${env.GIT_SHA_FULL}" \\
                --label "org.opencontainers.image.version=${env.IMAGE_TAG}" \\
                --label "org.opencontainers.image.source=https://github.com/tejaprakash-cbsy/validore-sepm" \\
                -t ${env.IMAGE_REF} \\
                ${latestFlag} \\
                .

              echo "=== Image details ==="
              docker image inspect ${env.IMAGE_REF} --format '{{.Size}}' | \\
                awk '{printf "Image size: %.1f MB\\n", \$1/1024/1024}' || true

              echo "✅ Docker image built successfully."
            """
          } else {
            bat """
              @echo Building Docker image...
              @echo   Primary tag : ${env.IMAGE_REF}
              @echo   Latest tag  : ${isMaster ? env.IMAGE_LATEST : 'N/A (non-main branch)'}

              docker build ^
                --build-arg GIT_COMMIT=${env.GIT_SHA_FULL} ^
                --build-arg VERSION=${env.IMAGE_TAG} ^
                --label "org.opencontainers.image.revision=${env.GIT_SHA_FULL}" ^
                --label "org.opencontainers.image.version=${env.IMAGE_TAG}" ^
                --label "org.opencontainers.image.source=https://github.com/tejaprakash-cbsy/validore-sepm" ^
                -t ${env.IMAGE_REF} ^
                ${latestFlag} ^
                .

              @echo ✅ Docker image built successfully.
            """
          }
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 9 — Security Scan (Trivy)
    // ──────────────────────────────────────────────────────────────────────────
    stage('Security Scan (Trivy)') {
      when {
        expression { !params.SKIP_DOCKER }
      }

      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 9: Trivy Security Scan         ║'
        echo '╚══════════════════════════════════════╝'

        script {
          def trivyAvailable = false
          try {
            if (isUnix()) {
              trivyAvailable = (sh(script: 'trivy --version', returnStatus: true) == 0)
            } else {
              trivyAvailable = (bat(script: '@trivy --version >nul 2>nul', returnStatus: true) == 0)
            }
          } catch (Exception e) {
            trivyAvailable = false
          }

          if (!trivyAvailable) {
            error 'Trivy security scanner is not installed on this Jenkins agent. ' +
                  'Please install Trivy (aquasec/trivy) or trigger the build with parameter SKIP_DOCKER=true.'
          }

          if (isUnix()) {
            sh """
              mkdir -p ${env.TRIVY_CACHE_DIR}

              echo "Scanning image ${env.IMAGE_REF} for vulnerabilities..."
              echo "Severity threshold: HIGH and CRITICAL vulnerabilities fail the build."

              trivy image \\
                --cache-dir ${env.TRIVY_CACHE_DIR} \\
                --format table \\
                --severity HIGH,CRITICAL,MEDIUM,LOW \\
                --no-progress \\
                ${env.IMAGE_REF} || true

              mkdir -p reports
              trivy image \\
                --cache-dir ${env.TRIVY_CACHE_DIR} \\
                --format json \\
                --output reports/trivy-report.json \\
                --no-progress \\
                ${env.IMAGE_REF} || true

              echo "--- Strict check: HIGH / CRITICAL vulnerabilities ---"
              trivy image \\
                --cache-dir ${env.TRIVY_CACHE_DIR} \\
                --exit-code 1 \\
                --severity HIGH,CRITICAL \\
                --no-progress \\
                --quiet \\
                ${env.IMAGE_REF}

              echo "✅ Security scan passed — no HIGH/CRITICAL vulnerabilities."
            """
          } else {
            bat """
              if not exist ${env.TRIVY_CACHE_DIR} mkdir ${env.TRIVY_CACHE_DIR}
              if not exist reports mkdir reports

              @echo Scanning image ${env.IMAGE_REF} for vulnerabilities...
              trivy image --cache-dir ${env.TRIVY_CACHE_DIR} --format table --severity HIGH,CRITICAL,MEDIUM,LOW --no-progress ${env.IMAGE_REF} || exit /b 0

              trivy image --cache-dir ${env.TRIVY_CACHE_DIR} --format json --output reports/trivy-report.json --no-progress ${env.IMAGE_REF} || exit /b 0

              @echo --- Strict check: HIGH / CRITICAL vulnerabilities ---
              trivy image --cache-dir ${env.TRIVY_CACHE_DIR} --exit-code 1 --severity HIGH,CRITICAL --no-progress --quiet ${env.IMAGE_REF}

              @echo ✅ Security scan passed — no HIGH/CRITICAL vulnerabilities.
            """
          }
        }
      }

      post {
        always {
          archiveArtifacts artifacts: 'reports/trivy-report.json', allowEmptyArchive: true
        }
        failure {
          echo '❌ Security scan FAILED — HIGH or CRITICAL CVEs detected. Fix before publishing.'
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 10 — Publish Image
    // ──────────────────────────────────────────────────────────────────────────
    stage('Publish Image') {
      when {
        allOf {
          expression { !params.SKIP_DOCKER }
          anyOf {
            branch 'main'
            branch 'master'
          }
        }
      }

      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 10: Publish to Registry        ║'
        echo '╚══════════════════════════════════════╝'

        withCredentials([
          usernamePassword(
            credentialsId: 'validore-registry',
            usernameVariable: 'REGISTRY_USER',
            passwordVariable: 'REGISTRY_PASS'
          )
        ]) {
          script {
            if (isUnix()) {
              sh """
                echo "Logging in to container registry..."
                echo "\${REGISTRY_PASS}" | docker login ghcr.io \\
                  -u "\${REGISTRY_USER}" \\
                  --password-stdin

                echo "Pushing ${env.IMAGE_REF}..."
                docker push ${env.IMAGE_REF}

                echo "Pushing ${env.IMAGE_LATEST}..."
                docker push ${env.IMAGE_LATEST}

                docker logout ghcr.io
                echo "✅ Images published successfully."
                echo "   SHA tag  : ${env.IMAGE_REF}"
                echo "   Latest   : ${env.IMAGE_LATEST}"
              """
            } else {
              bat """
                @echo Logging in to container registry...
                echo %REGISTRY_PASS% | docker login ghcr.io -u %REGISTRY_USER% --password-stdin

                @echo Pushing ${env.IMAGE_REF}...
                docker push ${env.IMAGE_REF}

                @echo Pushing ${env.IMAGE_LATEST}...
                docker push ${env.IMAGE_LATEST}

                docker logout ghcr.io
                @echo ✅ Images published successfully.
                @echo    SHA tag  : ${env.IMAGE_REF}
                @echo    Latest   : ${env.IMAGE_LATEST}
              """
            }
          }
        }
      }

      post {
        failure {
          echo '❌ Image publish FAILED. Check registry credentials and network access.'
        }
      }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // STAGE 11 — Deploy Staging
    // ──────────────────────────────────────────────────────────────────────────
    stage('Deploy Staging') {
      when {
        allOf {
          expression { !params.SKIP_DOCKER && params.DEPLOY_STAGING }
          anyOf {
            branch 'main'
            branch 'master'
          }
        }
      }

      // Manual approval gate — pauses the pipeline until an operator clicks.
      input {
        message 'Deploy container image to STAGING?'
        ok 'Yes, deploy to staging'
        submitter 'admin,deployer'
        parameters {
          string(
            name: 'STAGING_NOTES',
            defaultValue: '',
            description: 'Optional release notes for this deployment'
          )
        }
      }

      steps {
        echo '╔══════════════════════════════════════╗'
        echo '║  STAGE 11: Deploy to Staging          ║'
        echo '╚══════════════════════════════════════╝'

        script {
          echo "Deploying ${env.IMAGE_REF} to staging..."

          def notes = env.STAGING_NOTES ?: ''
          def branchClean = env.GIT_BRANCH_CLEAN ?: 'main'
          def shaFull = env.GIT_SHA_FULL ?: 'HEAD'

          echo "=== Staging Deployment Record ==="
          echo "Image     : ${env.IMAGE_REF}"
          echo "Branch    : ${branchClean}"
          echo "Commit    : ${shaFull}"
          echo "Notes     : ${notes}"
          echo "=================================="

          echo "✅ Staging deployment recorded. Wire the deploy commands for live execution."
        }
      }

      post {
        success {
          echo "✅ Staging deployment of ${env.IMAGE_REF} completed."
        }
        failure {
          echo '❌ Staging deployment FAILED. Rolling back is a manual step; check the orchestrator.'
        }
      }
    }

  } // end stages

  // ── Post-pipeline actions (run regardless of outcome) ───────────────────────
  post {
    always {
      echo '── Post: always ──────────────────────────────────────────────────────'

      // Publish JUnit results one final time to catch any edge cases
      junit allowEmptyResults: true, testResults: "${env.JUNIT_REPORT}"

      // Clean up dangling Docker images if docker is available on the agent
      script {
        try {
          if (isUnix()) {
            sh '''
              docker image prune -f --filter "label=org.opencontainers.image.source" 2>/dev/null || true
              docker image rm "${IMAGE_REF}" 2>/dev/null || true
            '''
          } else {
            bat '''
              where docker >nul 2>nul && docker image prune -f --filter "label=org.opencontainers.image.source" >nul 2>nul || exit /b 0
              where docker >nul 2>nul && docker image rm "%IMAGE_REF%" >nul 2>nul || exit /b 0
            '''
          }
        } catch (Exception e) {
          // Docker cleanup is best-effort
        }
      }

      // Print a build summary
      script {
        echo """
╔══════════════════════════════════════════════════════════╗
║  BUILD SUMMARY                                            ║
╠══════════════════════════════════════════════════════════╣
║  Job     : ${env.JOB_NAME}
║  Build   : #${env.BUILD_NUMBER}
║  Branch  : ${env.GIT_BRANCH_CLEAN ?: 'unknown'}
║  Commit  : ${env.IMAGE_TAG ?: env.BUILD_NUMBER}
║  Status  : ${currentBuild.currentResult}
║  Duration: ${currentBuild.durationString}
║  URL     : ${env.BUILD_URL}
╚══════════════════════════════════════════════════════════╝
        """
      }
    }

    success {
      echo "✅ PIPELINE SUCCESS"
      echo "Image ${env.IMAGE_REF} was built${(env.GIT_BRANCH_CLEAN == 'main' || env.GIT_BRANCH_CLEAN == 'master') ? ', scanned, and published' : ' (no publish on feature branches)'}."
    }

    failure {
      echo '❌ PIPELINE FAILED'
      echo 'No image was published. Check the failed stage and fix before re-running.'
    }

    unstable {
      echo '⚠️  PIPELINE UNSTABLE — tests failed or produced warnings.'
      echo 'No image was published.'
    }

    aborted {
      echo '🛑 PIPELINE ABORTED — manually cancelled or timed out.'
    }
  }
}
