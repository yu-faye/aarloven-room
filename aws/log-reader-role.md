# AWS Log Reader Role Setup

This document provides the exact AWS CLI commands and policies to create the IAM role that allows GitHub Actions to read CloudTrail events for the transparency log.

## Overview

The transparency log workflow uses GitHub's OIDC provider to assume an AWS IAM role with read-only CloudTrail access. This allows the workflow to query KMS and IAM events without storing long-lived AWS credentials.

## Prerequisites

- AWS CLI installed and configured with admin credentials
- AWS account ID (replace `ACCOUNT_ID` in commands below)
- This repository: `yu-faye/aarloven-room`

## Setup Steps

### 1. Create GitHub OIDC Provider (if not exists)

Check if the provider already exists:

```bash
aws iam get-open-id-connect-provider \
  --open-id-connect-provider-arn "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com" \
  2>/dev/null || echo "Provider does not exist"
```

If it doesn't exist, create it:

```bash
aws iam create-open-id-connect-provider \
  --url "https://token.actions.githubusercontent.com" \
  --client-id-list "sts.amazonaws.com" \
  --thumbprint-list "6938fd4d98bab03faadb97b34396831e3780aea1" \
  "1c58a3a8518e8759bf075b76b750d4f2df264fcd"
```

**Note**: The thumbprints are GitHub's current OIDC provider thumbprints. If GitHub rotates their certificates, these may need to be updated.

### 2. Create Trust Policy

Save this trust policy to `trust-policy.json` (replace `ACCOUNT_ID` with your AWS account ID):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:yu-faye/aarloven-room:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

**Security**: The trust policy is restricted to:
- This specific repository: `yu-faye/aarloven-room`
- The `main` branch only
- Prevents other repositories or branches from assuming this role

### 3. Create IAM Role

```bash
aws iam create-role \
  --role-name aarloven-public-log-reader \
  --assume-role-policy-document file://trust-policy.json \
  --description "Read-only CloudTrail access for Aarloven transparency log"
```

### 4. Create Permission Policy

Save this permission policy to `permission-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```

**Security**: This policy grants only the minimal permission needed:
- `cloudtrail:LookupEvents` — Query CloudTrail event history (read-only)
- No write permissions
- No access to other AWS services
- CloudTrail event history for management events cannot be edited or deleted for 90 days

### 5. Attach Permission Policy

```bash
aws iam put-role-policy \
  --role-name aarloven-public-log-reader \
  --policy-name CloudTrailReadOnly \
  --policy-document file://permission-policy.json
```

### 6. Get Role ARN

```bash
aws iam get-role \
  --role-name aarloven-public-log-reader \
  --query 'Role.Arn' \
  --output text
```

Save this ARN — you'll add it as a GitHub secret in the next step.

### 7. Add GitHub Secret

Go to your repository settings:
1. Navigate to **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. Name: `AWS_LOG_READER_ROLE_ARN`
4. Value: The ARN from step 6 (e.g., `arn:aws:iam::ACCOUNT_ID:role/aarloven-public-log-reader`)
5. Click **Add secret**

## Verification

Test the role assumption from a GitHub Actions workflow:

```yaml
- name: Configure AWS credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: ${{ secrets.AWS_LOG_READER_ROLE_ARN }}
    aws-region: eu-north-1

- name: Test CloudTrail access
  run: |
    aws cloudtrail lookup-events \
      --lookup-attributes AttributeKey=EventName,AttributeValue=PutKeyPolicy \
      --max-results 1
```

## Regions

The transparency log queries CloudTrail in two regions:
- **eu-north-1** — KMS events (production keys are in this region)
- **us-east-1** — IAM events (IAM is global, but events are recorded in us-east-1)

The role has permission to query CloudTrail in all regions.

## CloudTrail Event History

AWS CloudTrail provides **90 days** of event history for management events at no extra cost. The log collector queries this event history.

**Important limitations**:
- CloudTrail is in our AWS account — an account owner could theoretically stop CloudTrail or delete the trail
- However, the **event history for management events cannot be edited or deleted for 90 days** after they occur
- If the trail is stopped, a gap in the transparency log would be visible
- If credentials are removed, the log shows "kms feed not connected" rather than claiming zero changes

## Maintenance

### Rotating the Role

If you need to recreate the role:

1. Delete the old role:
   ```bash
   aws iam delete-role-policy \
     --role-name aarloven-public-log-reader \
     --policy-name CloudTrailReadOnly
   
   aws iam delete-role \
     --role-name aarloven-public-log-reader
   ```

2. Follow steps 3-7 above to create a new role

### Updating the Trust Policy

If the repository is renamed or moved:

1. Update `trust-policy.json` with the new repository name
2. Update the role's trust policy:
   ```bash
   aws iam update-assume-role-policy \
     --role-name aarloven-public-log-reader \
     --policy-document file://trust-policy.json
   ```

## Troubleshooting

### Error: "Not authorized to perform sts:AssumeRoleWithWebIdentity"

Check:
- The trust policy has the correct repository name and branch
- The OIDC provider exists
- The workflow has `id-token: write` permission

### Error: "User is not authorized to perform: cloudtrail:LookupEvents"

Check:
- The permission policy is attached to the role
- The policy document is valid JSON

### No events returned

Check:
- The date is within the last 90 days
- The region is correct (KMS events are in eu-north-1)
- The event name is correct (case-sensitive)

## Security Considerations

✅ **Read-only** — The role can only read CloudTrail events, not modify them

✅ **Repository-scoped** — Only this repository's `main` branch can assume the role

✅ **No secrets** — No long-lived credentials are stored; OIDC tokens are short-lived

✅ **Minimal permissions** — Only `cloudtrail:LookupEvents` is granted

⚠️ **Account-owned** — CloudTrail is in our account, so an account owner could stop it (but gaps would be visible)

⚠️ **90-day limit** — Event history is only available for 90 days (sufficient for daily collection)
