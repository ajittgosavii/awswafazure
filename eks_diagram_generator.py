"""
EKS Architecture Diagram Generator - SVG Edition
Creates professional AWS-style architecture diagrams
"""

import streamlit as st
from typing import Dict, List, Optional
from dataclasses import dataclass


class EKSArchitectureDiagram:
    """Generate professional SVG architecture diagrams for EKS"""
    
    # AWS-style colors
    COLORS = {
        'eks': '#FF9900',  # AWS Orange
        'compute': '#3F8624',  # Green
        'storage': '#7AA116',  # Light Green
        'network': '#5B9BD5',  # Blue
        'security': '#C24A43',  # Red
        'database': '#527FFF',  # Light Blue
        'background': '#FFFFFF',
        'text': '#232F3E',  # AWS Dark Blue
        'line': '#879596',  # Gray
        'karpenter': '#326CE5',  # Kubernetes Blue
    }
    
    @staticmethod
    def generate_svg(spec) -> str:
        """Generate complete SVG architecture diagram"""
        
        svg_width = 1200
        svg_height = 800
        
        svg_parts = []
        
        # SVG Header with defs for gradients and patterns
        svg_parts.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" 
     viewBox="0 0 {svg_width} {svg_height}" 
     width="{svg_width}" 
     height="{svg_height}">
  
  <!-- Definitions -->
  <defs>
    <!-- AWS Orange Gradient -->
    <linearGradient id="awsGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#FF9900;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#EC7211;stop-opacity:1" />
    </linearGradient>
    
    <!-- Blue Gradient for Network -->
    <linearGradient id="blueGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#5B9BD5;stop-opacity:0.3" />
      <stop offset="100%" style="stop-color:#4472C4;stop-opacity:0.3" />
    </linearGradient>
    
    <!-- Green Gradient for Compute -->
    <linearGradient id="greenGradient" x1="0%" y1="0%" x2="0%" y2="100%">
      <stop offset="0%" style="stop-color:#3F8624;stop-opacity:0.2" />
      <stop offset="100%" style="stop-color:#2D6219;stop-opacity:0.2" />
    </linearGradient>
    
    <!-- Shadow -->
    <filter id="shadow">
      <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.3"/>
    </filter>
    
    <!-- Glow for highlight -->
    <filter id="glow">
      <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
      <feMerge>
        <feMergeNode in="coloredBlur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>
  
  <!-- Background -->
  <rect width="{svg_width}" height="{svg_height}" fill="#F5F7FA"/>
  
  <!-- Title -->
  <text x="600" y="40" text-anchor="middle" font-family="Arial, sans-serif" 
        font-size="24" font-weight="bold" fill="#232F3E">
    {spec.project_name} - EKS Architecture
  </text>
  <text x="600" y="65" text-anchor="middle" font-family="Arial, sans-serif" 
        font-size="14" fill="#5A6C7D">
    {spec.environment} Environment | {spec.region}
  </text>
''')
        
        # VPC Container (large box)
        vpc_x, vpc_y = 50, 100
        vpc_width, vpc_height = 1100, 650
        
        svg_parts.append(f'''
  <!-- VPC Container -->
  <rect x="{vpc_x}" y="{vpc_y}" width="{vpc_width}" height="{vpc_height}" 
        fill="url(#blueGradient)" stroke="#5B9BD5" stroke-width="3" 
        rx="10" filter="url(#shadow)"/>
  <text x="{vpc_x + 20}" y="{vpc_y + 30}" font-family="Arial, sans-serif" 
        font-size="18" font-weight="bold" fill="#232F3E">
    🌐 VPC ({spec.region})
  </text>
''')
        
        # EKS Control Plane (top center)
        eks_x, eks_y = 450, 150
        eks_width, eks_height = 300, 80
        
        svg_parts.append(f'''
  <!-- EKS Control Plane -->
  <rect x="{eks_x}" y="{eks_y}" width="{eks_width}" height="{eks_height}" 
        fill="url(#awsGradient)" stroke="#EC7211" stroke-width="2" 
        rx="8" filter="url(#shadow)"/>
  <text x="{eks_x + eks_width/2}" y="{eks_y + 30}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="16" font-weight="bold" fill="white">
    🎯 EKS Control Plane
  </text>
  <text x="{eks_x + eks_width/2}" y="{eks_y + 50}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="12" fill="white">
    Version: {spec.eks_version}
  </text>
  <text x="{eks_x + eks_width/2}" y="{eks_y + 68}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="11" fill="white">
    Managed by AWS
  </text>
''')
        
        # Availability Zones
        az_width = 320
        az_height = 400
        az_y = 280
        
        for i, az in enumerate(spec.availability_zones[:3]):  # Show up to 3 AZs
            az_x = 100 + (i * 360)
            
            svg_parts.append(f'''
  <!-- Availability Zone {i+1} -->
  <rect x="{az_x}" y="{az_y}" width="{az_width}" height="{az_height}" 
        fill="url(#greenGradient)" stroke="#3F8624" stroke-width="2" 
        rx="5" stroke-dasharray="5,5"/>
  <text x="{az_x + 10}" y="{az_y + 25}" font-family="Arial, sans-serif" 
        font-size="14" font-weight="bold" fill="#232F3E">
    📍 AZ: {az}
  </text>
''')
            
            # Node Group in this AZ
            if i < len(spec.node_groups):
                ng = spec.node_groups[i]
                node_x = az_x + 20
                node_y = az_y + 50
                node_width = 280
                node_height = 150
                
                svg_parts.append(f'''
  <!-- Node Group {i+1} -->
  <rect x="{node_x}" y="{node_y}" width="{node_width}" height="{node_height}" 
        fill="#E8F5E9" stroke="#3F8624" stroke-width="2" rx="5" filter="url(#shadow)"/>
  <text x="{node_x + 10}" y="{node_y + 25}" font-family="Arial, sans-serif" 
        font-size="13" font-weight="bold" fill="#232F3E">
    💻 Node Group: {ng.get('name', f'ng-{i+1}')}
  </text>
  <text x="{node_x + 10}" y="{node_y + 45}" font-family="Arial, sans-serif" 
        font-size="11" fill="#5A6C7D">
    Instance: {ng.get('instance_type', 't3.medium')}
  </text>
  <text x="{node_x + 10}" y="{node_y + 62}" font-family="Arial, sans-serif" 
        font-size="11" fill="#5A6C7D">
    Capacity: {ng.get('min_size', 1)}-{ng.get('max_size', 5)} nodes
  </text>
  <text x="{node_x + 10}" y="{node_y + 79}" font-family="Arial, sans-serif" 
        font-size="11" fill="#5A6C7D">
    Type: {ng.get('capacity_type', 'ON_DEMAND')}
  </text>
  <text x="{node_x + 10}" y="{node_y + 96}" font-family="Arial, sans-serif" 
        font-size="10" fill="#7AA116">
    ✓ Auto Scaling Enabled
  </text>
''')
                
                # Connection from EKS to Node Group
                svg_parts.append(f'''
  <line x1="{eks_x + eks_width/2}" y1="{eks_y + eks_height}" 
        x2="{node_x + node_width/2}" y2="{node_y}" 
        stroke="#879596" stroke-width="2" stroke-dasharray="5,5"/>
''')
                
                # Pods inside node group
                for j in range(3):
                    pod_x = node_x + 20 + (j * 80)
                    pod_y = node_y + 115
                    
                    svg_parts.append(f'''
  <circle cx="{pod_x}" cy="{pod_y}" r="15" fill="#326CE5" stroke="#1E4BA8" stroke-width="1"/>
  <text x="{pod_x}" y="{pod_y + 5}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="10" fill="white">
    Pod
  </text>
''')
            
            # Subnet
            subnet_y = az_y + 220
            svg_parts.append(f'''
  <!-- Subnet -->
  <rect x="{az_x + 20}" y="{subnet_y}" width="{az_width - 40}" height="60" 
        fill="#FFFFFF" stroke="#5B9BD5" stroke-width="1" rx="3"/>
  <text x="{az_x + 35}" y="{subnet_y + 25}" font-family="Arial, sans-serif" 
        font-size="11" font-weight="bold" fill="#232F3E">
    🔒 Private Subnet
  </text>
  <text x="{az_x + 35}" y="{subnet_y + 43}" font-family="Arial, sans-serif" 
        font-size="9" fill="#5A6C7D">
    CIDR: 10.0.{i}.0/24
  </text>
''')
            
            # Load Balancer (only in first AZ)
            if i == 0 and spec.load_balancer_type:
                lb_y = az_y + 300
                svg_parts.append(f'''
  <!-- Load Balancer -->
  <rect x="{az_x + 50}" y="{lb_y}" width="{az_width - 100}" height="50" 
        fill="#FFF3CD" stroke="#FFC107" stroke-width="2" rx="5" filter="url(#shadow)"/>
  <text x="{az_x + az_width/2}" y="{lb_y + 25}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="12" font-weight="bold" fill="#232F3E">
    ⚖️ {spec.load_balancer_type.upper()} Load Balancer
  </text>
  <text x="{az_x + az_width/2}" y="{lb_y + 40}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="9" fill="#5A6C7D">
    Cross-Zone Enabled
  </text>
''')
        
        # Karpenter (if enabled)
        if spec.karpenter_enabled:
            karp_x, karp_y = 900, 250
            svg_parts.append(f'''
  <!-- Karpenter -->
  <rect x="{karp_x}" y="{karp_y}" width="200" height="100" 
        fill="#E3F2FD" stroke="#326CE5" stroke-width="2" rx="5" filter="url(#glow)"/>
  <text x="{karp_x + 100}" y="{karp_y + 30}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="14" font-weight="bold" fill="#1E4BA8">
    🚀 Karpenter
  </text>
  <text x="{karp_x + 100}" y="{karp_y + 50}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="10" fill="#5A6C7D">
    Auto-scaling Controller
  </text>
  <text x="{karp_x + 100}" y="{karp_y + 67}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="9" fill="#7AA116">
    ✓ Dynamic Provisioning
  </text>
  <text x="{karp_x + 100}" y="{karp_y + 82}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="9" fill="#7AA116">
    ✓ Cost Optimization
  </text>
  
  <!-- Connection to EKS -->
  <line x1="{eks_x + eks_width}" y1="{eks_y + eks_height/2}" 
        x2="{karp_x}" y2="{karp_y + 50}" 
        stroke="#326CE5" stroke-width="2"/>
''')
        
        # Add-ons section
        addon_y = 120
        addons_to_show = []
        
        if spec.enable_secrets_encryption:
            addons_to_show.append(('🔐 KMS Encryption', 150))
        if spec.enable_pod_security:
            addons_to_show.append(('🛡️ Pod Security', 280))
        if spec.monitoring_solution == 'CloudWatch':
            addons_to_show.append(('📊 CloudWatch', 410))
        
        for i, (addon_name, addon_x) in enumerate(addons_to_show):
            svg_parts.append(f'''
  <!-- Add-on: {addon_name} -->
  <rect x="{addon_x}" y="{addon_y}" width="110" height="35" 
        fill="#E8F5E9" stroke="#3F8624" stroke-width="1" rx="3"/>
  <text x="{addon_x + 55}" y="{addon_y + 22}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="10" fill="#232F3E">
    {addon_name}
  </text>
''')
        
        # Storage (if enabled)
        if spec.ebs_enabled or spec.efs_enabled:
            storage_x, storage_y = 900, 400
            storage_items = []
            
            if spec.ebs_enabled:
                storage_items.append('💾 EBS Volumes')
            if spec.efs_enabled:
                storage_items.append('📁 EFS File System')
            
            svg_parts.append(f'''
  <!-- Storage -->
  <rect x="{storage_x}" y="{storage_y}" width="200" height="{50 + len(storage_items) * 20}" 
        fill="#FFF3E0" stroke="#FF9800" stroke-width="2" rx="5" filter="url(#shadow)"/>
  <text x="{storage_x + 100}" y="{storage_y + 25}" text-anchor="middle" 
        font-family="Arial, sans-serif" font-size="13" font-weight="bold" fill="#232F3E">
    💽 Storage
  </text>
''')
            
            for i, storage in enumerate(storage_items):
                svg_parts.append(f'''
  <text x="{storage_x + 20}" y="{storage_y + 45 + i * 20}" 
        font-family="Arial, sans-serif" font-size="10" fill="#5A6C7D">
    {storage}
  </text>
''')
        
        # Legend
        legend_y = 720
        svg_parts.append(f'''
  <!-- Legend -->
  <text x="100" y="{legend_y}" font-family="Arial, sans-serif" 
        font-size="11" font-weight="bold" fill="#232F3E">
    Legend:
  </text>
  <rect x="160" y="{legend_y - 12}" width="15" height="15" fill="url(#awsGradient)"/>
  <text x="180" y="{legend_y}" font-family="Arial, sans-serif" font-size="9" fill="#5A6C7D">
    EKS Control Plane
  </text>
  
  <rect x="290" y="{legend_y - 12}" width="15" height="15" fill="#E8F5E9" stroke="#3F8624"/>
  <text x="310" y="{legend_y}" font-family="Arial, sans-serif" font-size="9" fill="#5A6C7D">
    Worker Nodes
  </text>
  
  <circle cx="407" cy="{legend_y - 5}" r="7" fill="#326CE5"/>
  <text x="420" y="{legend_y}" font-family="Arial, sans-serif" font-size="9" fill="#5A6C7D">
    Pods
  </text>
  
  <rect x="490" y="{legend_y - 12}" width="15" height="15" fill="#E3F2FD" stroke="#326CE5"/>
  <text x="510" y="{legend_y}" font-family="Arial, sans-serif" font-size="9" fill="#5A6C7D">
    Karpenter
  </text>
  
  <rect x="600" y="{legend_y - 12}" width="15" height="15" fill="#FFF3CD" stroke="#FFC107"/>
  <text x="620" y="{legend_y}" font-family="Arial, sans-serif" font-size="9" fill="#5A6C7D">
    Load Balancer
  </text>
''')
        
        # Footer
        svg_parts.append(f'''
  <!-- Footer -->
  <text x="1150" y="{legend_y + 30}" text-anchor="end" 
        font-family="Arial, sans-serif" font-size="8" fill="#879596">
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}
  </text>
</svg>
''')
        
        return ''.join(svg_parts)
    
    @staticmethod
    def display_diagram(spec):
        """Display the SVG diagram in Streamlit"""
        
        svg_content = EKSArchitectureDiagram.generate_svg(spec)
        
        # Display in Streamlit
        st.markdown("### 🏗️ EKS Architecture Diagram")
        st.components.v1.html(svg_content, height=850, scrolling=False)
        
        # Download button
        st.download_button(
            label="⬇️ Download SVG Diagram",
            data=svg_content,
            file_name=f"{spec.project_name.replace(' ', '_')}_eks_architecture.svg",
            mime="image/svg+xml",
            use_container_width=True
        )
        
        return svg_content


# Helper function for easy integration
def generate_eks_architecture_diagram(spec):
    """
    Easy-to-use function to generate and display EKS architecture diagram
    
    Usage:
        from eks_diagram_generator import generate_eks_architecture_diagram
        generate_eks_architecture_diagram(spec)
    """
    return EKSArchitectureDiagram.display_diagram(spec)
