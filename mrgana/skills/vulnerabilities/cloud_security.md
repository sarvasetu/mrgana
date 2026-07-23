---
name: cloud_security
description: Comprehensive cloud security testing for AWS, GCP, Azure, Kubernetes, and Docker including misconfigurations, IAM, storage, and network security
---

# Cloud Security Testing

## Overview
Cloud security testing covers misconfigurations, IAM policies, storage security, network configurations, and container security across major cloud providers.

## Tools Available in Sandbox

| Tool | Purpose | Command |
|------|---------|---------|
| **trivy** | Container/IaC scanning | `trivy image nginx:latest` |
| **scout** | Docker security | `scout cves nginx:latest` |
| **grype** | Container vulnerability scanner | `grype nginx:latest` |
| **semgrep** | IaC security rules | `semgrep --config p/terraform` |
| **checkov** | IaC security | `checkov -d .` |
| **tfsec** | Terraform security | `tfsec .` |
| **kubesec** | Kubernetes security | `kube-score render deployment.yaml` |

## Testing Methodology

### 1. AWS Security Testing

#### IAM Policy Analysis
```bash
# Check for overly permissive policies
aws iam get-account-authorization-details --query 'UserDetailList[*].PolicyList[*].PolicyDocument' --output json | jq '.[] | select(.Statement[] | .Effect == "Allow" and .Resource == "*")'

# Check for root account access keys
aws iam get-account-authorization-details --query 'UserDetailList[?UserName==`root`].AccessKeyMetadata'

# Check for unused IAM credentials
aws iam generate-credential-report && aws iam get-credential-report --query 'Content' --output text | base64 -d | grep -i "true"
```

#### S3 Bucket Security
```bash
# List all S3 buckets
aws s3api list-buckets --query 'Buckets[*].Name'

# Check bucket policies for public access
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    echo "Checking $bucket..."
    aws s3api get-bucket-policy --bucket $bucket --query 'Policy' --output text 2>/dev/null | jq '.Statement[] | select(.Effect == "Allow" and .Principal == "*")'
done

# Check bucket ACLs
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    aws s3api get-bucket-acl --bucket $bucket --query 'Grants[?Permission==`READ`]' --output json
done

# Check for public access blocks
for bucket in $(aws s3api list-buckets --query 'Buckets[*].Name' --output text); do
    aws s3api get-public-access-block --bucket $bucket 2>/dev/null
done
```

#### EC2 Security
```bash
# Check for public EC2 instances
aws ec2 describe-instances --query 'Reservations[*].Instances[*].{ID:InstanceId,PublicIP:PublicIpAddress,State:State.Name}' --output json | jq '.[] | select(.[] | .PublicIP != null)'

# Check security groups for open ports
aws ec2 describe-security-groups --query 'SecurityGroups[*].{ID:GroupId,Ingress:IpPermissions[*].{From:IpProtocol,Ports:IpRanges}}' --output json | jq '.[] | select(.Ingress[] | .Ports[] | .CidrIp == "0.0.0.0/0")'

# Check for unencrypted EBS volumes
aws ec2 describe-volumes --query 'Volumes[*].{ID:VolumeId,Encrypted:Encrypted,Size:Size}' --output json | jq '.[] | select(.Encrypted == false)'
```

#### Lambda Security
```bash
# Check for Lambda functions with public access
aws lambda list-functions --query 'Functions[*].{Name:FunctionName,Arn:FunctionArn}' --output json

# Check Lambda permissions
aws lambda get-policy --function-name <function-name> --query 'Policy' --output text | jq '.Statement[] | select(.Effect == "Allow" and .Principal == "*")'
```

#### RDS Security
```bash
# Check for public RDS instances
aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,Public:PubliclyAccessible,Encrypted:StorageEncrypted}' --output json | jq '.[] | select(.Public == true)'

# Check for unencrypted RDS
aws rds describe-db-instances --query 'DBInstances[*].{ID:DBInstanceIdentifier,Encrypted:StorageEncrypted}' --output json | jq '.[] | select(.Encrypted == false)'
```

### 2. GCP Security Testing

#### IAM Analysis
```bash
# Check for public IAM bindings
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" --format="json" | jq '.[] | select(.bindings[].members == "allUsers")'

# Check for overly permissive roles
gcloud projects get-iam-policy <project-id> --flatten="bindings[].members" --format="json" | jq '.[] | select(.bindings[].role | contains("admin"))'
```

#### Storage Security
```bash
# Check for public buckets
gsutil ls -p <project-id> | while read bucket; do
    echo "Checking $bucket..."
    gsutil iam get $bucket | jq '.bindings[] | select(.members == ["allUsers", "allAuthenticatedUsers"])'
done

# Check bucket ACLs
gsutil ls -p <project-id> | while read bucket; do
    gsutil acl get $bucket
done
```

#### Compute Engine Security
```bash
# Check for public VMs
gcloud compute instances list --format="json" | jq '.[] | select(.networkInterfaces[].accessConfigs[] | .natIP != null)'

# Check firewall rules
gcloud compute firewall-rules list --format="json" | jq '.[] | select(.sourceRanges[] == "0.0.0.0/0")'
```

### 3. Azure Security Testing

#### IAM Analysis
```bash
# Check for contributor/admin roles
az role assignment list --query "[?contains(roleDefinitionName, 'Contributor') || contains(roleDefinitionName, 'Owner')]" --output table

# Check for service principals with secrets
az ad sp list --query "[?passwordCredentials[0].keyId != null]" --output table
```

#### Storage Security
```bash
# Check for public storage accounts
az storage account list --query "[?allowBlobPublicAccess == true]" --output table

# Check for public containers
az storage container list --account-name <account-name> --query "[?properties.publicAccess == 'container']"
```

#### Network Security
```bash
# Check for open security groups
az network nsg rule list --nsg-name <nsg-name> --query "[?direction == 'Inbound' && sourceAddressPrefix == '*']"

# Check for public IPs
az network public-ip list --query "[?ipConfiguration != null]" --output table
```

### 4. Kubernetes Security Testing

#### RBAC Analysis
```bash
# Check for cluster-admin bindings
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name == "cluster-admin")'

# Check for overly permissive roles
kubectl get clusterroles -o json | jq '.items[] | select(.rules[] | .verbs[] == "*" and .resources[] == "*")'

# Check for service account tokens
kubectl get serviceaccounts -o json | jq '.items[] | select(.automountServiceAccountToken == true)'
```

#### Pod Security
```bash
# Check for privileged containers
kubectl get pods -o json | jq '.items[] | select(.spec.containers[] | .securityContext.privileged == true)'

# Check for containers running as root
kubectl get pods -o json | jq '.items[] | select(.spec.containers[] | .securityContext.runAsUser == 0)'

# Check for containers with host network
kubectl get pods -o json | jq '.items[] | select(.spec.hostNetwork == true)'
```

#### Network Policies
```bash
# Check for network policies
kubectl get networkpolicies

# Check for pods without network policies
kubectl get pods -o json | jq '.items[] | select(.metadata.labels | has("app") == false)'
```

#### Secrets Management
```bash
# Check for secrets in environment variables
kubectl get pods -o json | jq '.items[] | select(.spec.containers[] | .env[] | .valueFrom.secretKeyRef != null)'

# Check for secrets mounted as volumes
kubectl get pods -o json | jq '.items[] | select(.spec.volumes[] | .secret != null)'
```

### 5. Docker Security Testing

#### Image Security
```bash
# Scan Docker image with trivy
trivy image <image-name>:<tag>

# Check for vulnerabilities
trivy image --severity HIGH,CRITICAL <image-name>:<tag>

# Check for secrets in image
trivy image --scanners secret <image-name>:<tag>
```

#### Container Configuration
```bash
# Check running containers
docker ps --format "{{.ID}} {{.Image}} {{.Status}}"

# Check for privileged containers
docker inspect --format '{{.HostConfig.Privileged}}' $(docker ps -q)

# Check for containers with host network
docker inspect --format '{{.HostConfig.NetworkMode}}' $(docker ps -q)

# Check for containers running as root
docker exec <container-id> whoami
```

#### Dockerfile Security
```bash
# Check for latest tag
grep -n "FROM.*:latest" Dockerfile

# Check for running as root
grep -n "USER" Dockerfile

# Check for secrets in build args
grep -n "ARG.*PASSWORD\|ARG.*SECRET\|ARG.*KEY" Dockerfile

# Check for ADD vs COPY
grep -n "^ADD" Dockerfile
```

### 6. Infrastructure as Code (IaC) Security

#### Terraform Security
```bash
# Run tfsec
tfsec .

# Run checkov
checkov -d . --framework terraform

# Check for public access
grep -rn "0.0.0.0/0\|::/0" *.tf

# Check for unencrypted resources
grep -rn "encrypted.*=.*false\|enable_encryption.*=.*false" *.tf
```

#### CloudFormation Security
```bash
# Run cfn-nag
cfn_nag_scan --input-path .

# Check for public access
grep -rn "0.0.0.0/0\|::/0" *.yaml *.json

# Check for unencrypted resources
grep -rn "Encrypted: false\|Encryption: false" *.yaml
```

#### Kubernetes Manifests
```bash
# Run kube-score
kube-score score deployment.yaml

# Run kubesec
kubesec scan deployment.yaml

# Check for privileged containers
grep -n "privileged: true" deployment.yaml

# Check for host network
grep -n "hostNetwork: true" deployment.yaml
```

### 7. Network Security Testing

#### Firewall Rules
```bash
# AWS Security Groups
aws ec2 describe-security-groups --query 'SecurityGroups[*].IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]'

# GCP Firewall Rules
gcloud compute firewall-rules list --format="json" | jq '.[] | select(.sourceRanges[] == "0.0.0.0/0")'

# Azure NSGs
az network nsg rule list --nsg-name <nsg-name> --query "[?sourceAddressPrefix == '*']"
```

#### TLS/SSL Configuration
```bash
# Check TLS version
nmap --script ssl-enum-ciphers -p 443 <target>

# Check certificate expiry
openssl s_client -connect <target>:443 2>/dev/null | openssl x509 -noout -dates
```

### 8. Automated Cloud Scanner

```python
#!/usr/bin/env python3
"""Cloud security scanner"""
import subprocess
import json
from typing import Dict, List, Any

class CloudScanner:
    def __init__(self, provider: str = "aws"):
        self.provider = provider
        self.findings: List[Dict[str, Any]] = []
    
    def scan_s3_buckets(self):
        """Scan S3 buckets for misconfigurations"""
        result = subprocess.run(
            ["aws", "s3api", "list-buckets", "--query", "Buckets[*].Name", "--output", "text"],
            capture_output=True, text=True
        )
        
        for bucket in result.stdout.strip().split():
            # Check public access
            policy_result = subprocess.run(
                ["aws", "s3api", "get-bucket-policy", "--bucket", bucket, "--query", "Policy", "--output", "text"],
                capture_output=True, text=True
            )
            
            if policy_result.returncode == 0:
                try:
                    policy = json.loads(policy_result.stdout)
                    for statement in policy.get("Statement", []):
                        if statement.get("Effect") == "Allow" and statement.get("Principal") == "*":
                            self.findings.append({
                                "type": "S3_PUBLIC_ACCESS",
                                "severity": "HIGH",
                                "resource": bucket,
                                "description": "S3 bucket allows public access"
                            })
                except json.JSONDecodeError:
                    pass
    
    def scan_security_groups(self):
        """Scan security groups for open ports"""
        result = subprocess.run(
            ["aws", "ec2", "describe-security-groups", "--query", "SecurityGroups[*].{ID:GroupId,Ingress:IpPermissions}", "--output", "json"],
            capture_output=True, text=True
        )
        
        try:
            groups = json.loads(result.stdout)
            for group in groups:
                for rule in group.get("Ingress", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            self.findings.append({
                                "type": "SG_OPEN_PORT",
                                "severity": "MEDIUM",
                                "resource": group["ID"],
                                "description": f"Security group allows access from 0.0.0.0/0"
                            })
        except json.JSONDecodeError:
            pass
    
    def scan_iam(self):
        """Scan IAM for overprivileged users"""
        result = subprocess.run(
            ["aws", "iam", "get-account-authorization-details", "--query", "UserDetailList[*].{Name:UserName,Policies:PolicyList}", "--output", "json"],
            capture_output=True, text=True
        )
        
        try:
            users = json.loads(result.stdout)
            for user in users:
                for policy in user.get("Policies", []):
                    policy_doc = policy.get("PolicyDocument", {})
                    for statement in policy_doc.get("Statement", []):
                        if statement.get("Effect") == "Allow" and statement.get("Resource") == "*":
                            self.findings.append({
                                "type": "IAM_OVERPERMISSION",
                                "severity": "HIGH",
                                "resource": user["Name"],
                                "description": "IAM user has overly permissive policy"
                            })
        except json.JSONDecodeError:
            pass
    
    def run_all(self) -> List[Dict[str, Any]]:
        """Run all cloud security scans"""
        print(f"Starting {self.provider.upper()} security scan...")
        
        if self.provider == "aws":
            print("1. Scanning S3 buckets...")
            self.scan_s3_buckets()
            
            print("2. Scanning security groups...")
            self.scan_security_groups()
            
            print("3. Scanning IAM...")
            self.scan_iam()
        
        print(f"\nScan complete. Found {len(self.findings)} issues.")
        return self.findings

if __name__ == "__main__":
    import sys
    provider = sys.argv[1] if len(sys.argv) > 1 else "aws"
    scanner = CloudScanner(provider)
    scanner.run_all()
```

### 9. Common Cloud Vulnerabilities

| Vulnerability | Provider | Severity |
|---------------|----------|----------|
| Public S3 bucket | AWS | CRITICAL |
| Overly permissive IAM | All | HIGH |
| Unencrypted storage | All | HIGH |
| Public database | All | CRITICAL |
| Open security groups | All | HIGH |
| Default VPC usage | AWS | MEDIUM |
| Logging disabled | All | MEDIUM |
| Root account access | AWS | CRITICAL |
| Hardcoded credentials | All | CRITICAL |
| Unpatched instances | All | HIGH |
| Missing MFA | All | MEDIUM |
| Public container images | All | HIGH |
| Privileged containers | K8s | CRITICAL |
| Missing network policies | K8s | MEDIUM |
| Host network mode | K8s | HIGH |

### 10. Remediation Guidance

#### S3 Bucket Security
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::bucket-name/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

#### IAM Least Privilege
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::bucket-name",
        "arn:aws:s3:::bucket-name/*"
      ]
    }
  ]
}
```

#### Kubernetes Pod Security
```yaml
apiVersion: v1
kind: Pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

#### Terraform Security
```hcl
# Enable encryption
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "example" {
  bucket = aws_s3_bucket.example.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "example" {
  bucket = aws_s3_bucket.example.id

  block_public_acls   = true
  block_public_policy = true
}
```

## Validation Checklist

- [ ] No public S3 buckets
- [ ] IAM follows least privilege
- [ ] All storage encrypted
- [ ] No public databases
- [ ] Security groups restrict access
- [ ] Logging enabled
- [ ] MFA enabled for root
- [ ] No hardcoded credentials
- [ ] Instances are patched
- [ ] Container images scanned
- [ ] Kubernetes pods run as non-root
- [ ] Network policies enforced
- [ ] IaC security scanned
- [ ] TLS/SSL properly configured
- [ ] Monitoring and alerting enabled
