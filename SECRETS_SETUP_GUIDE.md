# AWS Secrets Configuration Guide

## Where to Put secrets.toml

Create this file: `.streamlit/secrets.toml` in your app directory

```
aws-waf-advisor-FINAL/
├── .streamlit/
│   └── secrets.toml  ← Create this file
├── streamlit_app.py
└── ... other files
```

## Supported Formats

### Format 1: Standard AWS Credentials ✅

```toml
ANTHROPIC_API_KEY = "sk-ant-your-key-here"

[aws]
access_key_id = "AKIA..."
secret_access_key = "..."
default_region = "us-east-1"
```

### Format 2: Management Account Credentials ✅

```toml
ANTHROPIC_API_KEY = "sk-ant-your-key-here"

[aws]
management_access_key_id = "AKIA..."
management_secret_access_key = "..."
default_region = "us-east-2"
```

**Note:** This format works! The connector now supports both naming conventions.

### Format 3: Multi-Account Setup ✅

```toml
ANTHROPIC_API_KEY = "sk-ant-your-key-here"

[aws]
access_key_id = "AKIA..."
secret_access_key = "..."
default_region = "us-east-1"

[aws.accounts.production]
access_key_id = "AKIA..."
secret_access_key = "..."
region = "us-east-1"
account_name = "Production"

[aws.accounts.development]
access_key_id = "AKIA..."
secret_access_key = "..."
region = "us-west-2"
account_name = "Development"
```

## All Supported Field Names

The connector checks for credentials in this order:

**Access Key:**
- `access_key_id` ✅
- `ACCESS_KEY_ID` ✅
- `aws_access_key_id` ✅
- `AWS_ACCESS_KEY_ID` ✅
- `management_access_key_id` ✅ NEW!
- `MANAGEMENT_ACCESS_KEY_ID` ✅ NEW!

**Secret Key:**
- `secret_access_key` ✅
- `SECRET_ACCESS_KEY` ✅
- `aws_secret_access_key` ✅
- `AWS_SECRET_ACCESS_KEY` ✅
- `management_secret_access_key` ✅ NEW!
- `MANAGEMENT_SECRET_ACCESS_KEY` ✅ NEW!

**Region:**
- `default_region` ✅
- `region` ✅
- `AWS_REGION` ✅

## Testing Your Configuration

1. Create `.streamlit/secrets.toml` with your credentials
2. Run: `streamlit run streamlit_app.py`
3. Check sidebar for "✅ AWS Connected"
4. If not connected, check Module Status for error details

## Troubleshooting

### "Not Connected" Error

1. **Check file location:**
   - Must be `.streamlit/secrets.toml` (note the dot!)
   - Must be in the same directory as `streamlit_app.py`

2. **Check TOML syntax:**
   - Strings must be in quotes: `"value"`
   - Section headers in brackets: `[aws]`
   - No spaces around `=` sign

3. **Check credentials:**
   - Access key format: `AKIA...` (20 characters)
   - Secret key: 40 characters
   - No extra spaces or newlines

4. **Restart app:**
   - Press Ctrl+C to stop
   - Run `streamlit run streamlit_app.py` again
   - Secrets are loaded on startup

### Error: "Could not connect to AWS"

- Verify credentials are valid
- Check IAM permissions
- Try AWS CLI: `aws sts get-caller-identity`
- Check region is correct

## Quick Start

1. Copy one of the example formats above
2. Replace with your actual credentials
3. Save as `.streamlit/secrets.toml`
4. Run the app
5. Check for ✅ AWS Connected

## Security Notes

- ⚠️ Never commit `secrets.toml` to git
- ⚠️ Add `.streamlit/` to `.gitignore`
- ✅ Use IAM roles when possible
- ✅ Rotate credentials regularly
- ✅ Use least-privilege permissions

## Examples Included

Check `.streamlit-examples/` folder for:
- `secrets.toml.standard` - Standard format
- `secrets.toml.management` - Management account format
- `secrets.toml.multiacccount` - Multi-account format

Copy the appropriate example to `.streamlit/secrets.toml` and edit.
