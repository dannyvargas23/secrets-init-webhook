# secrets-init-webhook

A Kubernetes mutating admission webhook that injects AWS Secrets Manager values as environment variables into any pod — without modifying application code, without creating Kubernetes Secret objects, and without storing secrets in etcd.

## How it works

1. You add `awssm:` prefixed placeholders to your pod's env vars
2. You annotate the pod with `secretsinit.io/inject: "true"`
3. The webhook intercepts the pod at creation and injects a `secrets-init` binary
4. At container startup, `secrets-init` resolves the placeholders from AWS Secrets Manager
5. `secrets-init` replaces itself with your original application — your app sees real values in `process.env` / `os.Getenv()`

Secret values exist only in process memory. The pod spec in etcd contains only the `awssm:` placeholders. `kubectl exec -- env` shows placeholders, not real values.

---

## Quick start

### Step 1: Store your secrets in AWS Secrets Manager

Store as a JSON object for multiple keys:

```json
{
  "DATABASE_URL": "postgres://user:pass@host:5432/mydb",
  "REDIS_URL": "redis://host:6379",
  "JWT_SECRET": "my-secret-key"
}
```

Or as a plain string for a single value.

### Step 2: Set up Pod Identity

Each application's ServiceAccount needs a Pod Identity Association that grants access to Secrets Manager:

```bash
# Create the association
aws eks create-pod-identity-association \
  --cluster-name <cluster> \
  --namespace <app-namespace> \
  --service-account <app-service-account> \
  --role-arn <role-with-sm-access>
```

The app's IAM role needs at minimum:

```json
{
  "Effect": "Allow",
  "Action": "secretsmanager:GetSecretValue",
  "Resource": "arn:aws:secretsmanager:<region>:<account>:secret:<prefix>*"
}
```

### Step 3: Reference secrets in your pod spec

Add the annotation and use `awssm:` prefixed values:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: myapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
      annotations:
        secretsinit.io/inject: "true"
    spec:
      serviceAccountName: myapp
      containers:
        - name: app
          image: myapp:latest
          env:
            - name: NODE_ENV
              value: "production"
            - name: DATABASE_URL
              value: "awssm:prod/myapp/config#DATABASE_URL"
            - name: REDIS_URL
              value: "awssm:prod/myapp/config#REDIS_URL"
            - name: JWT_SECRET
              value: "awssm:prod/myapp/config#JWT_SECRET"
            - name: STRIPE_KEY
              value: "awssm:prod/myapp/stripe"
```

That's it. Your app reads `process.env.DATABASE_URL` normally. No code changes.

### Step 4: Verify

```bash
# Check the pod spec — should show placeholders, NOT real values
kubectl get pod <pod-name> -o jsonpath='{.spec.containers[0].env}' | jq .

# Check the running process — should show real values
kubectl exec <pod-name> -- cat /proc/1/environ | tr '\0' '\n' | grep DATABASE_URL
```

> **Note:** `kubectl exec -- env` shows the pod spec env (placeholders). Only PID 1 has the resolved values. This is a security feature.

---

## Secret reference format

### Basic formats

```yaml
# Extract a key from a JSON secret
value: "awssm:prod/myapp/config#DATABASE_URL"

# Plain string secret (no key extraction)
value: "awssm:prod/myapp/api-token"

# Full ARN
value: "awssm:arn:aws:secretsmanager:us-east-1:123456:secret:prod/myapp/config-AbCdEf#DATABASE_URL"
```

Format: `awssm:<secret-name>[#<key>[#<version>]]`

### Version support

```yaml
# Current version (default)
value: "awssm:prod/myapp/config#DATABASE_URL"

# Previous version (useful during rotation)
value: "awssm:prod/myapp/config#DATABASE_URL#AWSPREVIOUS"

# Specific version ID
value: "awssm:prod/myapp/config#DATABASE_URL#v-abc123"
```

Supported version stages: `AWSCURRENT`, `AWSPREVIOUS`, `AWSPENDING`. Any other value is treated as a version ID.

### Inline interpolation

Embed secrets within a larger string using `${awssm:...}`:

```yaml
# Build a connection string from multiple secret keys
value: "postgres://${awssm:prod/myapp/config#DB_USER}:${awssm:prod/myapp/config#DB_PASSWORD}@db.example.com:5432/mydb"

# Mix secrets from different sources
value: "https://${awssm:prod/myapp/config#API_KEY}@api.example.com/${awssm:prod/myapp/config#TENANT_ID}"
```

### All supported Kubernetes env patterns

```yaml
# 1. Direct value
env:
  - name: DATABASE_URL
    value: "awssm:prod/myapp/config#DATABASE_URL"

# 2. From a ConfigMap (ConfigMap data contains awssm: placeholders)
envFrom:
  - configMapRef:
      name: myapp-env

# 3. From a Kubernetes Secret (Secret data contains awssm: placeholders)
envFrom:
  - secretRef:
      name: myapp-secrets

# 4. Single key from a ConfigMap
env:
  - name: DATABASE_URL
    valueFrom:
      configMapKeyRef:
        name: myapp-env
        key: DATABASE_URL

# 5. Single key from a Kubernetes Secret
env:
  - name: DATABASE_URL
    valueFrom:
      secretKeyRef:
        name: myapp-secrets
        key: DATABASE_URL
```

For patterns 2-5, the referenced ConfigMap or Secret stores the `awssm:` placeholder as its value. Kubernetes populates the env var with the placeholder, and `secrets-init` resolves it at startup.

---

## Example: ConfigMap-based deployment

Store all env config (secrets + non-secrets) in a ConfigMap. The ConfigMap is safe to commit to git — it only contains placeholders and plain config.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: myapp-env
  namespace: myapp
data:
  NODE_ENV: "production"
  PORT: "3000"
  LOG_LEVEL: "info"
  DATABASE_URL: "awssm:prod/myapp/config#DATABASE_URL"
  REDIS_URL: "awssm:prod/myapp/config#REDIS_URL"
  JWT_SECRET: "awssm:prod/myapp/config#JWT_SECRET"
  STRIPE_KEY: "awssm:prod/myapp/stripe#SECRET_KEY"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  namespace: myapp
spec:
  replicas: 2
  selector:
    matchLabels:
      app: myapp
  template:
    metadata:
      labels:
        app: myapp
      annotations:
        secretsinit.io/inject: "true"
    spec:
      serviceAccountName: myapp
      containers:
        - name: app
          image: myapp:latest
          ports:
            - containerPort: 3000
          envFrom:
            - configMapRef:
                name: myapp-env
```

---

## Annotations

| Annotation | Values | Description |
|---|---|---|
| `secretsinit.io/inject` | `"true"`, `"skip"` | Enable injection. `"skip"` disables for debugging. |
| `secretsinit.io/ignore-missing-secrets` | `"true"` | Continue with empty values if a secret can't be resolved. |
| `secretsinit.io/mutate-probes` | `"true"` | Wrap exec probe commands with secrets-init. |
| `secretsinit.io/aws-region` | e.g. `"us-west-2"` | Override AWS region for this pod. |
| `secretsinit.io/secret-init-image` | image ref | Override secrets-init image for this pod. |

---

## Deploying the webhook

### Prerequisites

- EKS cluster (Kubernetes >= 1.28) with Pod Identity Agent addon
- cert-manager installed
- Two ECR repositories: `secrets-init-webhook` and `secrets-init-secrets-init`

### 1. Enable Pod Identity Agent

```bash
aws eks create-addon --cluster-name <cluster> --addon-name eks-pod-identity-agent
```

### 2. Create IAM role (OpenTofu)

The webhook's IAM role needs ECR read access to discover image ENTRYPOINT/CMD from private repositories. It does NOT need Secrets Manager access — secrets are resolved by `secrets-init` inside the target pod using the target pod's own credentials.

```bash
cd deploy/tofu
tofu init && tofu apply \
  -var="aws_account_id=<account>" \
  -var="cluster_name=<cluster>" \
  -var="aws_region=us-east-1"
```

### 3. Build and push images

```bash
# Build both images
docker build --platform linux/amd64 --target webhook -t <ecr>/secrets-init-webhook:0.4.3 .
docker build --platform linux/amd64 --target secrets-init -t <ecr>/secrets-init-secrets-init:0.4.3 .

# Push
docker push <ecr>/secrets-init-webhook:0.4.3
docker push <ecr>/secrets-init-secrets-init:0.4.3
```

### 4. Deploy with Helm

Create a values file:

```yaml
# values-prod.yaml
image:
  repository: <ecr>/secrets-init-webhook
  digest: "sha256:<webhook-digest>"

aws:
  region: us-east-1

webhook:
  mutationMode: init-container

secretsInit:
  image:
    repository: <ecr>/secrets-init-secrets-init
    digest: "sha256:<secrets-init-digest>"
```

```bash
helm upgrade --install secrets-init-webhook ./deploy/helm/secrets-init-webhook --namespace secrets-init-system --create-namespace -f values-prod.yaml
```

### 5. Set up Pod Identity for your apps

For each namespace/ServiceAccount that needs secrets:

```bash
aws eks create-pod-identity-association \
  --cluster-name <cluster> \
  --namespace <app-namespace> \
  --service-account <app-sa> \
  --role-arn <role-with-sm-access>
```

### 6. Test

```bash
kubectl run test-inject -n <namespace> --image=busybox --restart=Never \
  --overrides='{"metadata":{"annotations":{"secretsinit.io/inject":"true"}},"spec":{"containers":[{"name":"test","image":"busybox:latest","command":["sh"],"args":["-c","echo DATABASE_URL=$DATABASE_URL && sleep 3600"],"env":[{"name":"DATABASE_URL","value":"awssm:<your-secret-name>#<key>"}]}]}}'

# Wait for pod to start, then check logs
kubectl logs test-inject -n <namespace>

# Clean up
kubectl delete pod test-inject -n <namespace>
```

---

## Production checklist

- [ ] Enable HPA (`autoscaling.enabled: true`, `minReplicas: 2`)
- [ ] Verify PDB is active (`minAvailable: 1`)
- [ ] Cluster spans at least 2 AZs (topology spread uses `DoNotSchedule`)
- [ ] Prometheus alerting configured (see below)

### Recommended alerts

| Alert | PromQL | Severity |
|---|---|---|
| Webhook denying pods | `rate(secrets-init_secrets_webhook_admission_requests_total{result="denied"}[5m]) > 0` | critical |
| p99 latency > 3s | `histogram_quantile(0.99, rate(secrets-init_secrets_webhook_admission_duration_seconds_bucket[5m])) > 3` | warning |
| Secret fetch errors | `rate(secrets-init_secrets_webhook_secret_resolutions_total{result="error"}[5m]) > 0` | critical |
| No webhook pods ready | `kube_deployment_status_replicas_available{deployment="secrets-init-webhook"} == 0` | critical |

Also monitor `apiserver_admission_webhook_rejection_count` from the API server metrics.

---

## Troubleshooting

**Container crashing with secrets-init error:**
```bash
# Check secrets-init logs
kubectl logs <pod> -c <container>

# Common causes:
# - Pod Identity Association not set up for the pod's ServiceAccount
# - Secret doesn't exist in Secrets Manager
# - IAM role doesn't have secretsmanager:GetSecretValue permission
```

**Webhook pods not starting:**
```bash
kubectl get ds -n kube-system eks-pod-identity-agent        # Pod Identity Agent running?
kubectl describe networkpolicy -n secrets-init-system              # Egress allowed?
kubectl get certificate -n secrets-init-system                     # TLS cert issued?
kubectl logs -n secrets-init-system -l app.kubernetes.io/name=secrets-init-webhook --tail=50
```

### Secret rotation

Secrets are resolved at container startup. Already-running pods keep their original values. To pick up rotated secrets, restart the pods:

```bash
kubectl rollout restart deployment/<app> -n <namespace>
```

Use [Stakater Reloader](https://github.com/stakater/Reloader) to automate restarts after rotation.

---

## Development

```bash
go mod download && go mod verify
go build -o webhook ./cmd/webhook
go build -o secrets-init ./cmd/secrets-init
go test -race ./...
golangci-lint run ./...
govulncheck ./...
```

Docker build (multi-target):
```bash
docker build --platform linux/amd64 --target webhook -t secrets-init-webhook .
docker build --platform linux/amd64 --target secrets-init -t secrets-init-secrets-init .
```

---

## Observability

| Signal | Endpoint | Details |
|---|---|---|
| Prometheus metrics | `:9090/metrics` | Admission request counts, durations, secret resolution counts |
| OTel traces | OTLP gRPC | Set `OTLP_ENDPOINT` to your collector |
| Structured logs | stdout (JSON) | zap production config |

---

## Security

- Secret values never touch etcd, the Kubernetes API, or disk — resolved in process memory only
- No Kubernetes Secret objects created
- `kubectl exec -- env` shows placeholders, not real values
- Webhook IAM role has ECR read only — no Secrets Manager access
- Pod Identity Association scoped to exact namespace + ServiceAccount
- TLS 1.3 minimum, PSA `restricted` profile, NetworkPolicy default deny
- `failurePolicy: Fail` — if the webhook is unavailable, pod creation is blocked rather than silently skipped
