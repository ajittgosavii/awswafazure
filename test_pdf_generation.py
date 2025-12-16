"""
PDF Report Generation Validation Script
Tests PDF generation functionality with sample data

Usage:
    python test_pdf_generation.py
"""

import sys
import os
from datetime import datetime
from io import BytesIO

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_pdf_generation():
    """Test PDF report generation"""
    
    print("=" * 80)
    print("PDF REPORT GENERATION VALIDATION")
    print("=" * 80)
    
    # Test 1: Check if reportlab is installed
    print("\n[Test 1] Checking reportlab installation...")
    try:
        import reportlab
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph
        print("✅ reportlab is installed")
        print(f"   Version: {reportlab.Version}")
    except ImportError as e:
        print(f"❌ reportlab is NOT installed: {e}")
        print("\n   Install with: pip install reportlab")
        return False
    
    # Test 2: Import PDF generator module
    print("\n[Test 2] Importing PDF generator module...")
    try:
        from pdf_report_generator import generate_comprehensive_waf_report
        print("✅ PDF generator module imported successfully")
    except ImportError as e:
        print(f"❌ Failed to import PDF generator: {e}")
        return False
    
    # Test 3: Create sample assessment data
    print("\n[Test 3] Creating sample assessment data...")
    try:
        from waf_framework_core import Pillar, RiskLevel
        from landscape_scanner import LandscapeAssessment, Finding, PillarScore, ResourceInventory
        
        # Create sample findings
        findings = [
            Finding(
                severity='HIGH',
                title='Security Group allows unrestricted access',
                description='Security group sg-12345 allows 0.0.0.0/0 on port 22',
                resource_id='sg-12345',
                resource_type='SecurityGroup',
                pillar='Security',
                remediation='Restrict SSH access to specific IP ranges'
            ),
            Finding(
                severity='MEDIUM',
                title='S3 bucket not encrypted',
                description='Bucket my-bucket does not have encryption enabled',
                resource_id='my-bucket',
                resource_type='S3Bucket',
                pillar='Security',
                remediation='Enable S3 bucket encryption'
            ),
            Finding(
                severity='LOW',
                title='CloudWatch logs retention period is short',
                description='Log group has retention of only 7 days',
                resource_id='/aws/lambda/my-function',
                resource_type='LogGroup',
                pillar='Operational Excellence',
                remediation='Increase retention to at least 30 days'
            )
        ]
        
        # Create sample pillar scores
        pillar_scores = {
            'Security': PillarScore(pillar='Security', score=65, high_risk_count=2, recommendations=['Enable GuardDuty', 'Implement MFA']),
            'Reliability': PillarScore(pillar='Reliability', score=78, high_risk_count=1, recommendations=['Implement Multi-AZ']),
            'Performance Efficiency': PillarScore(pillar='Performance Efficiency', score=82, high_risk_count=0, recommendations=[]),
            'Cost Optimization': PillarScore(pillar='Cost Optimization', score=70, high_risk_count=1, recommendations=['Right-size instances']),
            'Operational Excellence': PillarScore(pillar='Operational Excellence', score=75, high_risk_count=1, recommendations=['Automate deployments']),
            'Sustainability': PillarScore(pillar='Sustainability', score=68, high_risk_count=1, recommendations=['Use graviton instances'])
        }
        
        # Create sample resource inventory
        resources = ResourceInventory(
            ec2_count=25,
            rds_count=8,
            s3_count=42,
            lambda_count=37,
            vpc_count=3,
            total_cost_monthly=15750.50
        )
        
        # Create assessment
        assessment = LandscapeAssessment(
            assessment_id='test-assessment-001',
            timestamp=datetime.now(),
            regions_scanned=['us-east-1', 'us-west-2', 'eu-west-1'],
            accounts_scanned=['123456789012'],
            findings=findings,
            pillar_scores=pillar_scores,
            resources=resources,
            overall_score=73,
            overall_risk='MEDIUM'
        )
        
        print("✅ Sample assessment data created")
        print(f"   Assessment ID: {assessment.assessment_id}")
        print(f"   Overall Score: {assessment.overall_score}")
        print(f"   Findings: {len(findings)}")
        
    except Exception as e:
        print(f"❌ Failed to create sample data: {e}")
        return False
    
    # Test 4: Generate PDF
    print("\n[Test 4] Generating PDF report...")
    try:
        pdf_bytes = generate_comprehensive_waf_report(assessment)
        print(f"✅ PDF generated successfully")
        print(f"   PDF size: {len(pdf_bytes):,} bytes ({len(pdf_bytes) / 1024:.1f} KB)")
        
        # Save to file
        output_path = 'test_waf_report.pdf'
        with open(output_path, 'wb') as f:
            f.write(pdf_bytes)
        print(f"   PDF saved to: {output_path}")
        
    except Exception as e:
        print(f"❌ PDF generation failed: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    # Test 5: Validate PDF structure
    print("\n[Test 5] Validating PDF structure...")
    try:
        # Check if it's a valid PDF
        if pdf_bytes[:4] == b'%PDF':
            print("✅ Valid PDF header found")
        else:
            print("❌ Invalid PDF header")
            return False
        
        # Check if EOF marker exists
        if b'%%EOF' in pdf_bytes:
            print("✅ Valid PDF EOF marker found")
        else:
            print("⚠️  No EOF marker found (might still be valid)")
        
        # Check minimum size
        if len(pdf_bytes) > 10000:  # At least 10KB
            print(f"✅ PDF size is reasonable ({len(pdf_bytes) / 1024:.1f} KB)")
        else:
            print(f"⚠️  PDF size is small ({len(pdf_bytes) / 1024:.1f} KB)")
        
    except Exception as e:
        print(f"❌ PDF validation failed: {e}")
        return False
    
    print("\n" + "=" * 80)
    print("✅ ALL TESTS PASSED!")
    print("=" * 80)
    print(f"\nPDF report successfully generated: {output_path}")
    print("You can now open this file with any PDF reader to verify the content.")
    print("\nNext steps:")
    print("1. Open test_waf_report.pdf to verify content and formatting")
    print("2. Check that all sections are present:")
    print("   - Cover page with scores")
    print("   - Executive summary")
    print("   - Pillar assessments")
    print("   - Findings with details")
    print("   - Resource inventory")
    print("   - Remediation roadmap")
    print("3. Verify that formatting is professional and readable")
    
    return True

if __name__ == "__main__":
    try:
        success = test_pdf_generation()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
