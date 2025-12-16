# 🏗️ AWS Well-Architected Framework Advisor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-red.svg)](https://streamlit.io)
[![AWS](https://img.shields.io/badge/AWS-Focused-orange.svg)](https://aws.amazon.com)

> **Enterprise-grade AWS cloud architecture design and assessment platform with AI-powered recommendations**

## 🎯 What Is This?

A comprehensive platform for AWS cloud architects that combines:

- **🎨 Architecture Designer** - Design with NLP, Terraform, AWS scanning, or visual tools
- **☁️ AWS Environment Scanner** - Import and assess existing AWS infrastructure
- **⚡ Well-Architected Assessment** - Real-time WAF evaluation (200+ questions)
- **🤖 AI Assistant** - Claude-powered recommendations and conversational chat
- **📊 Multi-Account Management** - Enterprise portfolio tracking
- **🚀 EKS Modernization** - Container platform design and migration
- **💰 FinOps** - Cost optimization and analysis
- **🔒 Security & Compliance** - PCI-DSS, HIPAA, SOC 2, ISO 27001

## ✨ Key Features

### Architecture Design (4 Ways!)

1. **💬 Natural Language Input**
   ```
   "I need a production web app with EC2 Auto Scaling, 
    RDS PostgreSQL Multi-AZ, S3, and CloudFront"
   ```
   → AI parses and creates architecture automatically

2. **📄 Terraform Import**
   - Upload .tf files
   - Automatic visualization
   - Edit and re-export

3. **☁️ AWS Environment Scanning** ⭐ **POWERFUL!**
   - Scan your AWS accounts
   - Import all resources (EC2, RDS, S3, VPC, Lambda, EKS, etc.)
   - Instant WAF assessment
   - Identify security issues
   - Get AI recommendations

4. **🖱️ Visual Builder**
   - Drag-and-drop AWS services
   - Configure properties
   - Build architecture visually

### Real-Time WAF Assessment

- ⚡ Instant scoring as you design
- 🎯 6 pillar analysis (Security, Reliability, Performance, Cost, Ops, Sustainability)
- 🔍 Automatic issue detection
- 💡 AI-powered remediation recommendations
- 📊 Compliance reporting (PCI-DSS, HIPAA, SOC 2, ISO 27001)

### AI Integration (Claude by Anthropic)

- 🤖 Conversational WAF completion
- 💬 Chat interface for clarifications
- 📝 Automated documentation generation
- 🔧 Remediation script generation
- 💡 Best practice recommendations

### Enterprise Features

- 🏢 Multi-account AWS support
- 👥 Role-based access control
- 📊 Portfolio-wide analytics
- 📄 Automated compliance reporting
- 📤 Export to Terraform/CloudFormation
- 🔄 CI/CD integration

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- AWS Account (optional for scanning)
- Anthropic API Key (optional for AI features)

### Installation

```bash
# 1. Clone repository
git clone https://github.com/yourusername/aws-waf-advisor.git
cd aws-waf-advisor

# 2. Install dependencies
pip install -r requirements.txt

# 3. Configure AWS credentials (optional)
aws configure
# OR set environment variables

# 4. Run application
streamlit run streamlit_app.py
```

### First Use

1. Open browser to `http://localhost:8501`
2. **Try AWS Scanning:**
   - Go to "AWS Connector" → Configure credentials
   - Go to "Architecture Designer + WAF"
   - Select "☁️ Scan AWS Environment"
   - Click "Scan" and watch the magic! ✨

3. **Or Try NLP Design:**
   - Go to "Architecture Designer + WAF"
   - Select "💬 Natural Language"
   - Describe your architecture
   - Get instant WAF assessment!

## 📖 Core Modules

### Architecture & Design

- **modules_architecture_designer_waf.py** (45KB) - Main architecture design module
  - Natural language parsing
  - Terraform import/export
  - AWS environment scanning
  - Visual component builder
  - Real-time WAF integration
  - AI chat interface

- **modules_design_planning.py** (77KB) - Design workflows and templates
  - Blueprint management
  - Component library
  - Design patterns

### Assessment & Compliance

- **waf_review_module.py** (121KB) - Well-Architected Framework assessment
  - 200+ questions across 6 pillars
  - AI-powered recommendations
  - Automated issue detection

- **compliance_module.py** - Compliance frameworks
  - PCI-DSS, HIPAA, SOC 2, ISO 27001
  - Automated compliance checking

### AWS Integration

- **aws_connector.py** (19KB) - AWS credential management
- **landscape_scanner.py** (90KB) - Infrastructure discovery and scanning
- **multi_account_scanner.py** - Multi-account support
- **account_discovery.py** - AWS Organizations integration

### Specialized Tools

- **eks_modernization_module.py** (85KB) - EKS design and migration
- **finops_module.py** (47KB) - Cost optimization
- **modules_security_compliance.py** - Security automation
- **modules_vulnerability_management.py** - Vulnerability scanning
- **database_operations_dashboard.py** - Database management
- **network_operations_dashboard.py** - Network operations

## 🎨 Example: Scan Your AWS Environment

```bash
# Step 1: Configure AWS credentials
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=us-east-1

# Step 2: Run application
streamlit run streamlit_app.py

# Step 3: In the UI
# → Go to "Architecture Designer + WAF"
# → Select "☁️ Scan AWS Environment"
# → Choose region (e.g., us-east-1)
# → Click "Scan"

# Results:
# ✅ Found 47 resources
# ⚡ WAF Score: 78/100
# 🔍 Critical Issues: 8
# 💬 AI ready to discuss improvements
```

## 📊 What Gets Scanned

The AWS scanner discovers:

- **Compute:** EC2 instances, Auto Scaling groups, ECS clusters, EKS clusters, Lambda functions
- **Database:** RDS instances, DynamoDB tables, ElastiCache clusters
- **Storage:** S3 buckets (with encryption, versioning, lifecycle policies)
- **Network:** VPCs, Subnets, ALB/ELB, CloudFront distributions
- **Security:** Security Groups, IAM roles, KMS keys
- **And more...**

Then automatically:
- 📊 Visualizes architecture
- ⚡ Runs WAF assessment
- 🔍 Identifies security issues
- 💰 Analyzes costs
- 📋 Checks compliance
- 💡 Provides recommendations

## 🔧 Configuration

### Environment Variables

```bash
# AWS Credentials
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_DEFAULT_REGION=us-east-1

# Anthropic API (for AI features)
ANTHROPIC_API_KEY=your_api_key
```

### Streamlit Secrets

Or use `.streamlit/secrets.toml`:

```toml
[aws]
access_key_id = "your_key"
secret_access_key = "your_secret"
region = "us-east-1"

[anthropic]
api_key = "your_api_key"
```

## 🏢 Enterprise Use Cases

### 1. Document Existing Infrastructure
- Scan AWS accounts
- Auto-generate architecture diagrams
- Create documentation
- Track changes over time

### 2. Security & Compliance Audits
- Scan for security issues
- Check compliance (PCI, HIPAA, SOC 2)
- Generate audit reports
- Track remediation

### 3. Cloud Migration & Modernization
- Import existing infrastructure
- Design improved architecture
- Plan EKS migration
- Estimate costs

### 4. Multi-Account Management
- Scan multiple AWS accounts
- Portfolio-wide visibility
- Cross-account analytics
- Consolidated reporting

### 5. Cost Optimization
- Identify oversized resources
- Find unused resources
- Recommend reserved instances
- Track savings opportunities

## 📝 Documentation

- [Architecture Designer Guide](./ARCHITECTURE_DESIGNER_GUIDE.md) - Complete feature walkthrough
- [Setup Guide](./SETUP.md) - Installation and configuration
- [Contributing Guide](./CONTRIBUTING.md) - How to contribute

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md).

1. Fork the repository
2. Create feature branch
3. Make changes
4. Submit pull request

## 📝 License

MIT License - see [LICENSE](LICENSE) file.

## 🙏 Acknowledgments

- AWS Well-Architected Framework
- Anthropic Claude API
- Streamlit framework
- Open source community

## 🗺️ Roadmap

- [ ] Additional AWS service support
- [ ] Terraform auto-generation improvements
- [ ] Enhanced visual diagrams
- [ ] Real-time cost estimation
- [ ] Infrastructure drift detection
- [ ] Automated remediation scripts
- [ ] API for programmatic access
- [ ] VS Code extension

## 📞 Support

- 📧 Email: support@example.com
- 💬 Discussions: [GitHub Discussions](https://github.com/yourusername/aws-waf-advisor/discussions)
- 🐛 Issues: [GitHub Issues](https://github.com/yourusername/aws-waf-advisor/issues)

---

**Built with ❤️ for AWS Cloud Architects**

**Making AWS architecture design simple, fast, and compliant!** 🚀
