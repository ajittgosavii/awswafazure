# 🚀 AWS WAF Scanner Enterprise - Deployment Checklist

## Pre-Deployment Checklist

### **1. Prerequisites** ✅

- [ ] Python 3.10 or higher installed
- [ ] AWS CLI configured with credentials
- [ ] Access to target AWS accounts
- [ ] Git installed (if using CI/CD)
- [ ] Sufficient disk space (>1GB)

### **2. Package Extraction** ✅

```bash
# Extract enterprise package
unzip aws-waf-scanner-enterprise.zip
cd aws-waf-scanner-enterprise

# Verify contents
ls -la

# Expected files:
# - app_enterprise.py (NEW)
# - streamlit_app.py (existing)
# - waf_database.py (enhanced)
# - compliance_mapper.py (new)
# - cost_calculator.py (new)
# - remediation_engine.py (enhanced)
# - interactive_dashboard.py (new)
# - waf_cli.py (new)
# - requirements.txt (updated)
# - docs/ (documentation)
# - .github/workflows/ (CI/CD)
```

---

## Installation Steps

### **Step 1: Install Dependencies** ✅

```bash
# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate  # Windows

# Install all dependencies
pip install -r requirements.txt

# Verify critical packages
python -c "import click; print('✅ Click installed')"
python -c "import plotly; print('✅ Plotly installed')"
python -c "import pandas; print('✅ Pandas installed')"
python -c "import boto3; print('✅ Boto3 installed')"
python -c "import anthropic; print('✅ Anthropic installed')"
```

**Checklist:**
- [ ] Virtual environment created
- [ ] Dependencies installed
- [ ] All critical packages verified
- [ ] No error messages

---

### **Step 2: Initialize Database** ✅

```bash
# Initialize database with 11 tables
python -c "from waf_database import WAFDatabase; WAFDatabase(); print('✅ Database initialized!')"

# Verify database exists
ls -la waf_scanner.db

# Should see: waf_scanner.db (created)
```

**Checklist:**
- [ ] Database file created (`waf_scanner.db`)
- [ ] No errors during initialization
- [ ] File size > 0 bytes

---

### **Step 3: Configure AWS Credentials** ✅

**Option A: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

**Option B: AWS CLI Configuration**
```bash
aws configure
# Enter access key, secret key, region
```

**Option C: Streamlit Secrets (Recommended for Production)**
```bash
# Create .streamlit/secrets.toml
mkdir -p .streamlit
cat > .streamlit/secrets.toml << EOF
[aws]
access_key_id = "your_access_key"
secret_access_key = "your_secret_key"
default_region = "us-east-1"

[claude]
api_key = "your_claude_api_key"
EOF

# Secure the file
chmod 600 .streamlit/secrets.toml
```

**Checklist:**
- [ ] AWS credentials configured
- [ ] Claude API key configured (optional)
- [ ] Credentials tested with `aws sts get-caller-identity`

---

### **Step 4: Test Installation** ✅

```bash
# Test enterprise modules
python -c "
from waf_database import WAFDatabase
from compliance_mapper import ComplianceMapper
from cost_calculator import CostImpactCalculator
from interactive_dashboard import InteractiveDashboard
from remediation_engine import RemediationEngine
print('✅ All enterprise modules loaded successfully!')
"

# Test CLI tool
python waf_cli.py --help

# Should show CLI help text
```

**Checklist:**
- [ ] All modules import without errors
- [ ] CLI tool displays help
- [ ] No missing dependencies

---

## Deployment Options

### **Option 1: Local Development** ✅

```bash
# Start enterprise app
streamlit run app_enterprise.py

# OR start existing app
streamlit run streamlit_app.py

# Access at: http://localhost:8501
```

**Checklist:**
- [ ] App starts without errors
- [ ] Browser opens automatically or manually navigate to localhost:8501
- [ ] All tabs load correctly
- [ ] Can see feature status in sidebar

---

### **Option 2: Docker Deployment** ✅

```bash
# Build Docker image
docker build -t waf-scanner-enterprise:4.0 .

# Run container
docker run -d \
  --name waf-scanner \
  -p 8501:8501 \
  -e AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
  -e AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
  -v $(pwd)/waf_scanner.db:/app/waf_scanner.db \
  waf-scanner-enterprise:4.0

# Verify container
docker ps
docker logs waf-scanner

# Access at: http://localhost:8501
```

**Checklist:**
- [ ] Docker image builds successfully
- [ ] Container starts
- [ ] Logs show no errors
- [ ] App accessible on port 8501
- [ ] Database persists (volume mounted)

---

### **Option 3: AWS ECS/Fargate Deployment** ✅

```bash
# 1. Create ECR repository
aws ecr create-repository --repository-name waf-scanner-enterprise

# 2. Build and push image
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin $AWS_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com
docker tag waf-scanner-enterprise:4.0 $AWS_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/waf-scanner-enterprise:4.0
docker push $AWS_ACCOUNT.dkr.ecr.us-east-1.amazonaws.com/waf-scanner-enterprise:4.0

# 3. Create ECS task definition
# 4. Create ECS service
# 5. Configure load balancer
```

**Checklist:**
- [ ] ECR repository created
- [ ] Docker image pushed
- [ ] ECS task definition created
- [ ] ECS service running
- [ ] Load balancer configured
- [ ] SSL certificate added (for HTTPS)

---

## CI/CD Setup

### **GitHub Actions Setup** ✅

```bash
# 1. Ensure workflow file exists
ls .github/workflows/waf-scan.yml

# 2. Add repository secrets (in GitHub UI):
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
# - AWS_ACCOUNT_ID
# - SLACK_WEBHOOK_URL (optional)

# 3. Commit and push
git add .github/workflows/waf-scan.yml
git commit -m "Add WAF security scan workflow"
git push

# 4. Verify workflow runs
# Go to GitHub → Actions tab
```

**Checklist:**
- [ ] Workflow file exists in `.github/workflows/`
- [ ] Repository secrets added
- [ ] Workflow triggers on PR
- [ ] Workflow runs successfully
- [ ] SARIF uploaded to Security tab
- [ ] PR comments appear

---

### **GitLab CI Setup** ✅

```bash
# 1. Ensure pipeline file exists
ls .gitlab-ci.yml

# 2. Add CI/CD variables (in GitLab UI):
# Settings → CI/CD → Variables
# - AWS_ACCESS_KEY_ID
# - AWS_SECRET_ACCESS_KEY
# - AWS_ACCOUNT_ID
# - GITLAB_TOKEN
# - SLACK_WEBHOOK_URL (optional)

# 3. Commit and push
git add .gitlab-ci.yml
git commit -m "Add WAF security scan pipeline"
git push

# 4. Verify pipeline runs
# Go to GitLab → CI/CD → Pipelines
```

**Checklist:**
- [ ] Pipeline file exists
- [ ] CI/CD variables added
- [ ] Pipeline triggers automatically
- [ ] All stages pass
- [ ] Security dashboard updated
- [ ] MR comments appear

---

## Post-Deployment Verification

### **Step 1: Run First Scan** ✅

```bash
# Using web interface
streamlit run app_enterprise.py
# Navigate to WAF Scanner tab
# Select account(s)
# Click "Run Scan"

# OR using CLI
python waf_cli.py scan \
  --account-id 123456789012 \
  --region us-east-1 \
  --output test-scan.json
```

**Checklist:**
- [ ] Scan completes successfully
- [ ] Results display in UI
- [ ] Findings show compliance mappings
- [ ] Findings show cost impact
- [ ] Findings show remediation code
- [ ] PDF report generates
- [ ] Scan stored in database

---

### **Step 2: Verify Enterprise Features** ✅

**Historical Tracking:**
```bash
# Check database
sqlite3 waf_scanner.db "SELECT COUNT(*) FROM scan_history;"
# Should return > 0

# View trends in UI
# Go to Historical Trends tab
# Select account
# See trend charts
```

**Interactive Dashboards:**
```bash
# Go to Dashboard tab
# See 7 chart types:
# - Severity pie chart
# - WAF pillar radar
# - Trend lines
# - Service breakdown
# - Cost waterfall
# - Compliance heatmap
# - Finding age histogram
```

**Compliance Mapping:**
```bash
# Go to Compliance tab
# See framework violations:
# - CIS AWS Foundations
# - PCI-DSS v4.0
# - HIPAA
# - SOC 2
# - NIST CSF
```

**Cost Impact:**
```bash
# Go to Cost Impact tab
# See metrics:
# - Monthly waste
# - Annual waste
# - Risk exposure
# - Total impact
# - Top opportunities
```

**Remediation:**
```bash
# Go to Remediation tab
# Select a finding
# See 4 tabs:
# - Terraform code
# - CloudFormation template
# - AWS CLI commands
# - Manual steps
```

**Checklist:**
- [ ] Historical tracking works
- [ ] All 7 charts display
- [ ] Compliance mappings show
- [ ] Cost calculations correct
- [ ] Remediation code generates
- [ ] Can assign findings (Collaboration tab)
- [ ] Can add comments

---

### **Step 3: Test CLI Integration** ✅

```bash
# Run CLI scan
python waf_cli.py scan \
  --account-id 123456789012 \
  --output cli-test.json \
  --format json

# Test quality gates
python waf_cli.py scan \
  --account-id 123456789012 \
  --max-critical 0 \
  --max-high 5 \
  --min-waf-score 75 \
  --fail-on critical

# Generate SARIF
python waf_cli.py scan \
  --account-id 123456789012 \
  --output test.sarif \
  --format sarif

# Generate Markdown
python waf_cli.py scan \
  --account-id 123456789012 \
  --output test.md \
  --format markdown
```

**Checklist:**
- [ ] CLI scan works
- [ ] Quality gates enforce correctly
- [ ] SARIF format generates
- [ ] Markdown format generates
- [ ] Exit codes correct (0 = pass, 1 = fail)

---

## Team Onboarding

### **Step 1: Training Materials** ✅

Share documentation:
- [ ] `README_ENTERPRISE.md` - Overview
- [ ] `docs/QUICK_REFERENCE.md` - Commands
- [ ] `docs/IMPLEMENTATION_GUIDE.md` - Detailed setup

### **Step 2: Demo Session** ✅

Demonstrate:
- [ ] Running a scan
- [ ] Viewing dashboards
- [ ] Checking compliance
- [ ] Calculating costs
- [ ] Generating remediation code
- [ ] Assigning findings
- [ ] Adding comments
- [ ] Viewing trends

### **Step 3: Access Setup** ✅

For each team member:
- [ ] AWS credentials configured
- [ ] App access granted
- [ ] Email registered for assignments
- [ ] Notification preferences set

---

## Production Checklist

### **Security** ✅

- [ ] AWS credentials secured (no hardcoded keys)
- [ ] Streamlit secrets file permissions set (`chmod 600`)
- [ ] HTTPS enabled (for remote access)
- [ ] Firewall rules configured
- [ ] Database backups enabled
- [ ] Audit logging enabled

### **Performance** ✅

- [ ] Database indexed properly
- [ ] Scans scheduled during off-peak hours
- [ ] Rate limiting configured
- [ ] Resource limits set
- [ ] Monitoring enabled

### **Monitoring** ✅

- [ ] Application logs configured
- [ ] Error tracking enabled
- [ ] Performance metrics collected
- [ ] Alerting set up (Slack/Teams/Email)
- [ ] Dashboard accessible

### **Backup & Recovery** ✅

- [ ] Database backup schedule created
- [ ] Backup verification tested
- [ ] Recovery procedure documented
- [ ] DR plan created

---

## Troubleshooting Common Issues

### **Issue: Module not found**
```bash
# Solution
pip install -r requirements.txt
```

### **Issue: Database locked**
```bash
# Solution
python -c "
import sqlite3
conn = sqlite3.connect('waf_scanner.db')
conn.execute('PRAGMA journal_mode=WAL')
conn.close()
"
```

### **Issue: Charts not displaying**
```bash
# Solution
pip install plotly>=5.17.0
streamlit cache clear
```

### **Issue: AWS credentials not found**
```bash
# Solution
aws configure
# OR
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
```

---

## Success Criteria

### **Deployment Successful When:** ✅

- [x] All dependencies installed
- [x] Database initialized
- [x] App starts without errors
- [x] First scan completes successfully
- [x] All 8 tabs load correctly
- [x] Historical data saves
- [x] Compliance mappings display
- [x] Cost calculations work
- [x] Remediation code generates
- [x] CLI tool functional
- [x] CI/CD pipeline runs (if configured)
- [x] Team can access and use
- [x] Documentation reviewed

---

## Next Steps After Deployment

1. **Week 1:** Monitor usage, collect feedback
2. **Week 2:** Optimize quality gates based on results
3. **Week 3:** Set up scheduled scans
4. **Week 4:** Review trends and metrics
5. **Ongoing:** Train new users, update documentation

---

## Support Resources

**Documentation:**
- `docs/QUICK_REFERENCE.md` - Daily use
- `docs/IMPLEMENTATION_GUIDE.md` - Technical details
- `docs/TROUBLESHOOTING.md` - Common issues

**Code Examples:**
- See inline comments in all modules
- Check `examples/` directory

**Community:**
- Review GitHub Issues (if applicable)
- Check Stack Overflow for common questions

---

**✅ Deployment Complete!**

Your AWS WAF Scanner Enterprise Edition is now fully deployed and operational!
