import os
from graphviz import Digraph

# Ensure deliverables directory exists
os.makedirs('deliverables', exist_ok=True)

dot = Digraph('HardenedApp', format='png')
dot.attr(bgcolor='white')

# EC2 Instance
dot.node('ec2', 'EC2 Instance\n(Hardened Host)', shape='box3d', style='filled', fillcolor='#e1f5fe')

# Docker Daemon
dot.node('docker', 'Docker Daemon\n(hardened daemon.json)', shape='component', style='filled', fillcolor='#b3e5fc')
dot.edge('ec2', 'docker')

# Docker Networks
dot.node('frontend', 'frontend network', shape='ellipse', style='dashed', color='blue')
dot.node('backend', 'backend network', shape='ellipse', style='dashed', color='green')

# Web Container
dot.node('web', '''Web Container
- USER: appuser
- HEALTHCHECK
- read_only: true
- mem_limit: 256m
- pids_limit: 100
- no-new-privileges
- Exposes: 127.0.0.1:15000->5000
- .env for secrets
''', shape='box', style='filled', fillcolor='#fff9c4')

# DB Container
dot.node('db', '''DB Container (Postgres)
- read_only: true
- mem_limit: 512m
- pids_limit: 100
- no-new-privileges
- .env for secrets
''', shape='box', style='filled', fillcolor='#c8e6c9')

# Edges for containers and networks
dot.edge('docker', 'web')
dot.edge('docker', 'db')
dot.edge('web', 'frontend', label='connects to')
dot.edge('db', 'backend', label='connects to')

# Security Group
dot.node('sg', '''Security Group
- SSH: restricted
- No public app/db access
''', shape='note', style='filled', fillcolor='#ffcdd2')
dot.edge('ec2', 'sg', style='dotted')

# Save diagram
output_path = 'deliverables/architecture_diagram'
dot.render(output_path, view=False)
print(f"Diagram saved as {output_path}.png")