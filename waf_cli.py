"""
WAF Scanner CLI Tool
Command-line interface for CI/CD integration
"""

import click
import json
import sys
import os
from datetime import datetime
from typing import Dict, Optional
import boto3


class WAFScannerCLI:
    """CLI wrapper for WAF Scanner"""
    
    def __init__(self):
        self.session = None
        self.output_formats = ['json', 'junit', 'sarif', 'markdown']
    
    def run_scan(self, account_id: str, region: str = 'us-east-1', 
                 services: Optional[list] = None) -> Dict:
        """Run WAF scan"""
        
        # In production, this would import and run the actual scanner
        print(f"🔍 Scanning account: {account_id}")
        print(f"📍 Region: {region}")
        
        # Mock results for demonstration
        results = {
            'scan_id': datetime.now().strftime('%Y%m%d_%H%M%S'),
            'account_id': account_id,
            'scan_date': datetime.now().isoformat(),
            'total_findings': 15,
            'critical_count': 2,
            'high_count': 5,
            'medium_count': 6,
            'low_count': 2,
            'overall_waf_score': 68.5,
            'findings': []
        }
        
        return results
    
    def check_quality_gates(self, results: Dict, config: Dict) -> tuple:
        """Check if scan results pass quality gates"""
        
        gates = []
        passed = True
        
        # Check severity thresholds
        if 'max_critical' in config:
            critical_count = results.get('critical_count', 0)
            gate_passed = critical_count <= config['max_critical']
            gates.append({
                'name': 'Max Critical Findings',
                'passed': gate_passed,
                'actual': critical_count,
                'threshold': config['max_critical']
            })
            if not gate_passed:
                passed = False
        
        if 'max_high' in config:
            high_count = results.get('high_count', 0)
            gate_passed = high_count <= config['max_high']
            gates.append({
                'name': 'Max High Findings',
                'passed': gate_passed,
                'actual': high_count,
                'threshold': config['max_high']
            })
            if not gate_passed:
                passed = False
        
        if 'min_waf_score' in config:
            waf_score = results.get('overall_waf_score', 0)
            gate_passed = waf_score >= config['min_waf_score']
            gates.append({
                'name': 'Minimum WAF Score',
                'passed': gate_passed,
                'actual': waf_score,
                'threshold': config['min_waf_score']
            })
            if not gate_passed:
                passed = False
        
        return passed, gates
    
    def output_json(self, results: Dict, filepath: str):
        """Output results as JSON"""
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
    
    def output_junit(self, results: Dict, filepath: str):
        """Output results as JUnit XML"""
        
        total = results.get('total_findings', 0)
        failures = results.get('critical_count', 0) + results.get('high_count', 0)
        
        xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<testsuites>
  <testsuite name="WAF Security Scan" tests="{total}" failures="{failures}" errors="0" time="0">
'''
        
        # Add test cases for findings
        for severity in ['critical', 'high', 'medium', 'low']:
            count = results.get(f'{severity}_count', 0)
            if count > 0:
                if severity in ['critical', 'high']:
                    xml += f'''    <testcase name="{severity.title()} Severity Findings" classname="WAFScan">
      <failure message="{count} {severity} severity findings detected"/>
    </testcase>
'''
                else:
                    xml += f'''    <testcase name="{severity.title()} Severity Findings" classname="WAFScan"/>
'''
        
        xml += '''  </testsuite>
</testsuites>'''
        
        with open(filepath, 'w') as f:
            f.write(xml)
    
    def output_sarif(self, results: Dict, filepath: str):
        """Output results as SARIF format"""
        
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AWS WAF Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-org/waf-scanner",
                        "rules": []
                    }
                },
                "results": []
            }]
        }
        
        # Add findings as results
        severity_map = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note'
        }
        
        for finding in results.get('findings', []):
            sarif['runs'][0]['results'].append({
                "ruleId": finding.get('id', 'unknown'),
                "level": severity_map.get(finding.get('severity', 'MEDIUM'), 'warning'),
                "message": {
                    "text": finding.get('title', 'Unknown finding')
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get('resource', 'unknown')
                        }
                    }
                }]
            })
        
        with open(filepath, 'w') as f:
            json.dump(sarif, f, indent=2)
    
    def output_markdown(self, results: Dict, filepath: str):
        """Output results as Markdown"""
        
        md = f'''# AWS WAF Security Scan Report

**Scan ID:** {results.get('scan_id')}  
**Account:** {results.get('account_id')}  
**Date:** {results.get('scan_date')}

## 📊 Summary

| Metric | Value |
|--------|-------|
| Total Findings | {results.get('total_findings', 0)} |
| Critical | {results.get('critical_count', 0)} |
| High | {results.get('high_count', 0)} |
| Medium | {results.get('medium_count', 0)} |
| Low | {results.get('low_count', 0)} |
| **WAF Score** | **{results.get('overall_waf_score', 0):.1f}/100** |

## 🎯 Status

'''
        
        critical = results.get('critical_count', 0)
        high = results.get('high_count', 0)
        
        if critical > 0:
            md += f"❌ **FAILED**: {critical} critical findings must be resolved\n\n"
        elif high > 5:
            md += f"⚠️  **WARNING**: {high} high severity findings detected\n\n"
        else:
            md += "✅ **PASSED**: No critical issues found\n\n"
        
        md += "## 📋 Detailed Findings\n\n"
        
        # Group by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            findings = [f for f in results.get('findings', []) 
                       if f.get('severity') == severity]
            
            if findings:
                icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢'}
                md += f"### {icon[severity]} {severity} Severity\n\n"
                
                for finding in findings:
                    md += f"- **{finding.get('title')}**\n"
                    md += f"  - Service: {finding.get('service')}\n"
                    md += f"  - Resource: {finding.get('resource')}\n\n"
        
        with open(filepath, 'w') as f:
            f.write(md)


@click.group()
def cli():
    """AWS WAF Scanner CLI"""
    pass


@cli.command()
@click.option('--account-id', required=True, help='AWS Account ID to scan')
@click.option('--region', default='us-east-1', help='AWS Region')
@click.option('--output', default='report.json', help='Output file path')
@click.option('--format', type=click.Choice(['json', 'junit', 'sarif', 'markdown']), 
              default='json', help='Output format')
@click.option('--fail-on', type=click.Choice(['critical', 'high', 'medium', 'low']),
              help='Fail if findings of this severity or higher are found')
@click.option('--max-critical', type=int, help='Maximum allowed critical findings')
@click.option('--max-high', type=int, help='Maximum allowed high findings')
@click.option('--min-waf-score', type=float, help='Minimum required WAF score')
@click.option('--services', help='Comma-separated list of services to scan')
def scan(account_id, region, output, format, fail_on, max_critical, max_high, 
         min_waf_score, services):
    """Run WAF security scan"""
    
    scanner = WAFScannerCLI()
    
    # Parse services
    service_list = services.split(',') if services else None
    
    # Run scan
    click.echo(f"🚀 Starting WAF scan...")
    results = scanner.run_scan(account_id, region, service_list)
    
    # Save results
    if format == 'json':
        scanner.output_json(results, output)
    elif format == 'junit':
        scanner.output_junit(results, output)
    elif format == 'sarif':
        scanner.output_sarif(results, output)
    elif format == 'markdown':
        scanner.output_markdown(results, output)
    
    click.echo(f"✅ Report saved to: {output}")
    
    # Check quality gates
    quality_config = {}
    if max_critical is not None:
        quality_config['max_critical'] = max_critical
    if max_high is not None:
        quality_config['max_high'] = max_high
    if min_waf_score is not None:
        quality_config['min_waf_score'] = min_waf_score
    
    if quality_config:
        passed, gates = scanner.check_quality_gates(results, quality_config)
        
        click.echo("\n📏 Quality Gates:")
        for gate in gates:
            status = "✅ PASS" if gate['passed'] else "❌ FAIL"
            click.echo(f"  {status} {gate['name']}: {gate['actual']} (threshold: {gate['threshold']})")
        
        if not passed:
            click.echo("\n❌ Quality gates FAILED")
            sys.exit(1)
        else:
            click.echo("\n✅ Quality gates PASSED")
    
    # Check fail-on threshold
    if fail_on:
        severity_levels = ['critical', 'high', 'medium', 'low']
        threshold_index = severity_levels.index(fail_on)
        
        for level in severity_levels[:threshold_index + 1]:
            count = results.get(f'{level}_count', 0)
            if count > 0:
                click.echo(f"\n❌ FAILED: Found {count} {level.upper()} findings")
                sys.exit(1)
    
    click.echo(f"\n✅ Scan completed successfully")
    sys.exit(0)


@cli.command()
@click.argument('config_file', type=click.Path(exists=True))
def check_gates(config_file):
    """Check quality gates from configuration file"""
    
    with open(config_file, 'r') as f:
        if config_file.endswith('.json'):
            config = json.load(f)
        else:
            # Assume scan results
            results = json.load(f)
    
    scanner = WAFScannerCLI()
    
    # Quality gates from environment or config
    gates_config = {
        'max_critical': int(os.getenv('WAF_MAX_CRITICAL', 0)),
        'max_high': int(os.getenv('WAF_MAX_HIGH', 5)),
        'min_waf_score': float(os.getenv('WAF_MIN_SCORE', 80))
    }
    
    passed, gates = scanner.check_quality_gates(results, gates_config)
    
    click.echo("📏 Quality Gate Results:")
    for gate in gates:
        status = "✅ PASS" if gate['passed'] else "❌ FAIL"
        click.echo(f"  {status} {gate['name']}: {gate['actual']} (threshold: {gate['threshold']})")
    
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    cli()
