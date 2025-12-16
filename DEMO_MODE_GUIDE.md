# Demo Mode User Guide

## Overview

The AWS WAF Scanner Enterprise includes a **Demo/Live Mode Toggle** that allows you to:

- **Demo Mode (🎭)**: Run the full application with simulated data - no AWS credentials required
- **Live Mode (🔴)**: Connect to real AWS accounts for actual WAF assessments

## How to Use

### Switching Modes

1. Look at the **sidebar** on the left side of the application
2. Find the **🎮 Mode Selection** section at the top
3. Click either:
   - **🎭 Demo** - Switch to simulated data
   - **🔴 Live** - Switch to real AWS connection

### Demo Mode Features

When Demo Mode is active, you'll see:

1. **Orange Banner** at the top indicating "DEMO MODE - Using Simulated Data"
2. **Simulated AWS Connection** showing demo account details
3. **Full Functionality** - All features work with realistic sample data

#### Demo Data Includes:

| Category | Sample Data |
|----------|-------------|
| **AWS Accounts** | 5 demo accounts (Production, Development, Staging, Security, Shared Services) |
| **Resources** | ~500 simulated resources (EC2, RDS, S3, Lambda, EKS, etc.) |
| **WAF Findings** | ~60+ findings across all 6 WAF pillars |
| **Compliance** | Full status for CIS, PCI-DSS, HIPAA, SOC2, NIST CSF |
| **Cost Data** | Monthly costs, savings opportunities, trends |

### Live Mode Features

When Live Mode is active:

1. **Green indicators** show real connection status
2. **AWS Credentials Required** - Configure in AWS Connector tab
3. **Real Scanning** - Actual AWS API calls to your accounts

## Use Cases

### Demo Mode Best For:

- 🎯 **Sales Demonstrations** - Show capabilities without client AWS access
- 📚 **Training Sessions** - Learn the tool safely
- 🧪 **Feature Testing** - Explore without AWS costs
- 🎨 **UI Development** - Work on interface without backend
- ✈️ **Offline Work** - No internet/AWS required

### Live Mode Best For:

- 🔍 **Production Assessments** - Real WAF evaluations
- 📊 **Compliance Audits** - Actual compliance status
- 🔧 **Remediation Planning** - Based on real findings
- 📈 **Trend Analysis** - Historical tracking of your AWS

## Demo Scan Walkthrough

1. **Ensure Demo Mode is Active** (check sidebar)
2. Go to **🔍 WAF Scanner** tab
3. Select scan options:
   - Scan Mode: Quick/Standard/Comprehensive
   - Demo Account to scan
   - AWS Region
   - WAF Pillars to assess
4. Click **🚀 Run Demo Scan**
5. View simulated results including:
   - WAF Score and summary metrics
   - Findings by pillar
   - Resource inventory
   - Compliance status
   - Cost optimization opportunities

## Technical Details

### Demo Data Generator

The demo system uses `demo_mode_manager.py` which:

- Generates consistent, realistic sample data
- Uses a seeded random generator for reproducibility
- Provides data for all application modules
- Maintains session state for demo interactions

### Customizing Demo Data

You can modify demo data in `demo_mode_manager.py`:

```python
# Adjust resource counts
config.resource_count_multiplier = 2.0  # Double all counts

# Change WAF score range
config.waf_score_range = (70, 95)  # Higher scores

# Modify issue distribution
config.issue_severity_distribution = {
    "critical": 0.02,  # Fewer critical
    "high": 0.10,
    "medium": 0.38,
    "low": 0.50
}
```

## FAQ

**Q: Does Demo Mode make any AWS API calls?**
A: No. Demo Mode is completely offline and uses only simulated data.

**Q: Can I switch modes during a session?**
A: Yes! Click the mode buttons in the sidebar anytime. Your session data will update accordingly.

**Q: Is demo data saved anywhere?**
A: Demo data exists only in your browser session and is not persisted.

**Q: Can I customize the demo accounts?**
A: Yes, modify the `get_demo_accounts()` method in `demo_mode_manager.py`.

---

**Version:** 4.0.0  
**Last Updated:** December 2024
