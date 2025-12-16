# 🔒 AssumeRole Setup Guide

## Why AssumeRole?

**AssumeRole** is the AWS-recommended secure way for organizations to provide access without sharing long-term IAM credentials.

### Benefits

✅ **More Secure**
- Temporary credentials expire automatically (1-12 hours)
- No long-term credentials to leak or steal

✅ **Better Audit Trail**
- CloudTrail logs show who assumed which role
- Clear separation of identities

✅ **Enterprise Standard**
- Recommended by AWS Security
- Required for many compliance frameworks
- Follows AWS Well-Architected Framework

✅ **Easy to Revoke**
- Remove trust policy to revoke access
- No need to rotate credentials

---

## Single Account Setup

### For the Organization (Account Being Scanned)

#### Step 1: Create IAM Role

Role Name: `WAFAdvisorRole`

Trust Policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:user/scanner-user"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "waf-advisor-external-id-123"
        }
      }
    }
  ]
}
```

Replace:
- `111111111111` - Scanner's AWS account ID
- `scanner-user` - Scanner's IAM user name
- `waf-advisor-external-id-123` - Shared secret (generate with `openssl rand -hex 32`)

Permissions Policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:Describe*",
        "s3:GetBucketLocation",
        "s3:ListAllMyBuckets",
        "iam:GetAccountSummary",
        "cloudwatch:DescribeAlarms",
        "lambda:List*",
        "dynamodb:Describe*",
        "ecs:Describe*",
        "eks:Describe*"
      ],
      "Resource": "*"
    }
  ]
}
```

Or simply attach AWS managed policy: `ReadOnlyAccess`

#### Step 2: Provide Information

Share with scanner:
- **Role ARN:** `arn:aws:iam::222222222222:role/WAFAdvisorRole`
- **External ID:** `waf-advisor-external-id-123`

### For the Scanner (Running the Tool)

#### Step 1: Grant AssumeRole Permission

Add policy to your IAM user:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::222222222222:role/WAFAdvisorRole"
    }
  ]
}
```

#### Step 2: Configure in Tool

**Option A: Via UI**

1. Go to AWS Connector tab
2. Click "🔒 AssumeRole" tab
3. Enter your base credentials
4. Enter role ARN: `arn:aws:iam::222222222222:role/WAFAdvisorRole`
5. Enter external ID: `waf-advisor-external-id-123`
6. Click "Test AssumeRole"
7. Click "Assume Role & Connect"

**Option B: Via secrets.toml**

```toml
# .streamlit/secrets.toml
ANTHROPIC_API_KEY = "sk-ant-..."

[aws]
# Your base credentials
access_key_id = "AKIA..."
secret_access_key = "..."
default_region = "us-east-1"

# Role to assume
role_arn = "arn:aws:iam::222222222222:role/WAFAdvisorRole"
external_id = "waf-advisor-external-id-123"
```

---

## Multi-Account Setup

### For the Organization (Multiple Accounts)

#### Step 1: Choose Hub Account

Usually your management or security account.

Hub Account ID: `111111111111`

#### Step 2: Create Role in Each Target Account

In **each** target account (Production, Dev, Staging, etc.), create:

Role Name: `WAFAdvisorRole` (same name in all accounts)

Trust Policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::111111111111:user/scanner-user"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "org-external-id-2024"
        }
      }
    }
  ]
}
```

Permissions: Attach `ReadOnlyAccess` or custom read policy

#### Step 3: Grant Hub User Permission

In hub account (111111111111), attach policy to scanner user:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": [
        "arn:aws:iam::222222222222:role/WAFAdvisorRole",
        "arn:aws:iam::333333333333:role/WAFAdvisorRole",
        "arn:aws:iam::444444444444:role/WAFAdvisorRole"
      ]
    }
  ]
}
```

Or use wildcard (less secure):
```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::*:role/WAFAdvisorRole"
}
```

#### Step 4: Provide Information

Share with scanner:
- **Hub account credentials** (IAM user in hub account)
- **Role name:** `WAFAdvisorRole`
- **External ID:** `org-external-id-2024`
- **List of account IDs:** 222222222222, 333333333333, 444444444444, etc.

### For the Scanner

#### Configure in Tool

**Option A: Via UI**

1. Go to AWS Connector tab
2. Select "Multi-Account" mode
3. Click "🔒 AssumeRole Setup" tab
4. Enter hub account credentials
5. Click "Save Hub Credentials"
6. Add each account:
   - Account Name: "Production"
   - Account ID: "222222222222"
   - Role Name: "WAFAdvisorRole"
   - External ID: "org-external-id-2024"
7. Click "Add Account with AssumeRole"
8. Test each account
9. Run multi-account scan

**Option B: Via secrets.toml**

```toml
# .streamlit/secrets.toml
ANTHROPIC_API_KEY = "sk-ant-..."

[aws]
# Hub account credentials
access_key_id = "AKIA..."
secret_access_key = "..."
default_region = "us-east-1"

# Target accounts with AssumeRole
[[aws.accounts]]
account_name = "Production"
account_id = "222222222222"
role_name = "WAFAdvisorRole"
external_id = "org-external-id-2024"
region = "us-east-1"

[[aws.accounts]]
account_name = "Development"
account_id = "333333333333"
role_name = "WAFAdvisorRole"
external_id = "org-external-id-2024"
region = "us-west-2"

[[aws.accounts]]
account_name = "Staging"
account_id = "444444444444"
role_name = "WAFAdvisorRole"
external_id = "org-external-id-2024"
region = "us-east-1"
```

---

## Quick Reference

### Single Account
| Who | What | Details |
|-----|------|---------|
| **Organization** | Create role | `WAFAdvisorRole` with trust policy |
| **Organization** | Share | Role ARN + External ID |
| **Scanner** | Add policy | Grant `sts:AssumeRole` permission |
| **Scanner** | Configure | Enter base creds + role ARN in tool |

### Multi-Account
| Who | What | Details |
|-----|------|---------|
| **Organization** | Create roles | Same role name in all accounts |
| **Organization** | Share | Hub creds + role name + external ID + account IDs |
| **Scanner** | Configure | Hub creds + add accounts with role info |
| **Scanner** | Scan | Tool assumes role in each account automatically |

---

## Troubleshooting

### "User is not authorized to perform: sts:AssumeRole"

**Fix:** Add sts:AssumeRole permission to scanner's IAM user

### "Access denied"

**Fix:** Check trust policy allows scanner's account/user

### "External ID mismatch"

**Fix:** Ensure external ID matches in both:
- Trust policy Condition
- Tool configuration

### "Role doesn't exist"

**Fix:** Verify role ARN is correct and role exists

---

## Security Best Practices

1. ✅ **Always use External ID** - Prevents "confused deputy" problem
2. ✅ **Generate random External ID** - Use `openssl rand -hex 32`
3. ✅ **Use least privilege permissions** - ReadOnly access only
4. ✅ **Monitor AssumeRole calls** - Set up CloudWatch alarms
5. ✅ **Rotate External ID periodically** - Every 90-180 days
6. ✅ **Document your setup** - Keep trust policies documented
7. ✅ **Test before production** - Use "Test AssumeRole" button

---

## Complete Example

### Scenario
- Scanner account: 111111111111
- Scanner user: `security-scanner`
- Target account: 222222222222 (Production)
- External ID: `prod-scan-2024-xyz123`

### Step-by-Step

**1. Target Account (222222222222) - Create Role:**
```bash
# Role Name: WAFAdvisorRole
# Trust Policy: Allow 111111111111 user security-scanner
# External ID required: prod-scan-2024-xyz123
# Permissions: ReadOnlyAccess
```

**2. Scanner Account (111111111111) - Grant Permission:**
```json
{
  "Effect": "Allow",
  "Action": "sts:AssumeRole",
  "Resource": "arn:aws:iam::222222222222:role/WAFAdvisorRole"
}
```

**3. Tool Configuration:**
```toml
[aws]
access_key_id = "AKIA..." # security-scanner credentials
secret_access_key = "..."
role_arn = "arn:aws:iam::222222222222:role/WAFAdvisorRole"
external_id = "prod-scan-2024-xyz123"
```

**4. Test:**
- Click "Test AssumeRole"
- Should show success with account 222222222222

**5. Scan:**
- Click "Assume Role & Connect"
- Start WAF scan with temporary credentials

---

## Additional Resources

- [AWS AssumeRole Documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
- [IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [External ID Documentation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html)

---

**AssumeRole is the recommended secure way for production environments!** 🔒
