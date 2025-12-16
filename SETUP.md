# 🚀 Setup Guide - AWS WAF Advisor

## Quick Setup (5 Minutes)

### Step 1: Install Python

Ensure Python 3.9+ is installed:

```bash
python --version
# Should show Python 3.9.x or higher
```

### Step 2: Clone Repository

```bash
git clone https://github.com/yourusername/aws-waf-advisor.git
cd aws-waf-advisor
```

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Run Application

```bash
streamlit run streamlit_app.py
```

Application will open at: http://localhost:8501

---

## Detailed Setup

### 1. AWS Configuration (Optional)

#### Option A: Environment Variables

```bash
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1
```

#### Option B: AWS CLI Configuration

```bash
aws configure
```

#### Option C: IAM Instance Profile

If running on EC2, attach IAM role with required permissions.

### 2. Anthropic API Setup (Optional)

For AI features, get API key from: https://console.anthropic.com

```bash
export ANTHROPIC_API_KEY=your_api_key
```

Or add to `.streamlit/secrets.toml`:

```toml
ANTHROPIC_API_KEY = "your_api_key"
```

### 3. Firebase Setup (Optional)

For multi-user authentication:

1. Create Firebase project: https://console.firebase.google.com
2. Download service account key
3. Add to `.streamlit/secrets.toml`:

```toml
[firebase]
api_key = "your_api_key"
project_id = "your_project_id"
# ... other credentials
```

---

## Testing Installation

### 1. Basic Test

```bash
streamlit run streamlit_app.py
```

Visit http://localhost:8501

### 2. Test Architecture Designer

1. Click "Architecture Designer + WAF" tab
2. Select "💬 Natural Language"
3. Type: "I need a web app with EC2 and RDS"
4. Click "Generate Architecture"
5. Should see components created!

### 3. Test AWS Scanning (if configured)

1. Go to "AWS Connector" tab
2. Test connection
3. Go to "Architecture Designer"
4. Select "☁️ Scan AWS Environment"
5. Click "Scan"
6. Should see your resources!

---

## Troubleshooting

### Issue: Module not found

```bash
pip install --upgrade -r requirements.txt
```

### Issue: AWS credentials error

Check credentials:

```bash
aws sts get-caller-identity
```

### Issue: Anthropic API error

Verify API key:

```bash
# In Python:
import anthropic
client = anthropic.Anthropic(api_key="your_key")
# Should not error
```

### Issue: Port already in use

Use different port:

```bash
streamlit run streamlit_app.py --server.port 8502
```

---

## Production Deployment

### Docker

```bash
# Build
docker build -t aws-waf-advisor .

# Run
docker run -p 8501:8501 aws-waf-advisor
```

### Cloud Deployment

- **AWS**: Deploy to ECS or App Runner
- **Azure**: Deploy to App Service
- **GCP**: Deploy to Cloud Run
- **Heroku**: Use Procfile

---

## Next Steps

1. ✅ Install complete
2. ✅ Configure credentials
3. ✅ Test basic features
4. 📖 Read [Architecture Designer Guide](./ARCHITECTURE_DESIGNER_GUIDE.md)
5. 🎨 Design your first architecture!
6. ⚡ Run WAF assessment
7. 💬 Chat with AI assistant

**You're ready to go!** 🚀
