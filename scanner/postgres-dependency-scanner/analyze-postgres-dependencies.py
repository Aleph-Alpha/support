#!/usr/bin/env python3
"""
Analyze PostgreSQL dependencies across projects from image-source-analysis.json
to assess migration effort to MSDB (Microsoft SQL Server Database).
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Optional
import sys

# PostgreSQL-related patterns to search for
POSTGRES_PATTERNS = [
    # Python packages
    r'psycopg[23]?',
    r'asyncpg',
    r'pg8000',
    r'py-postgresql',
    r'postgresql',
    r'postgres',
    r'sqlalchemy.*postgres',
    r'tortoise-orm',
    r'django.*postgres',
    r'peewee.*postgres',
    # Go packages
    r'github\.com/lib/pq',
    r'github\.com/jackc/pgx',
    r'gorm\.io/driver/postgres',
    r'postgres',
    # Rust crates
    r'postgres',
    r'tokio-postgres',
    r'sqlx.*postgres',
    r'diesel.*postgres',
    # Node.js packages
    r'pg[^a-z]',
    r'node-postgres',
    r'pg-promise',
    r'sequelize',
    r'typeorm',
    r'prisma',
    r'knex',
    # Generic
    r'libpq',
    r'postgresql-client',
    r'postgres-client',
]

def is_postgres_dependency(text: str) -> bool:
    """Check if text contains PostgreSQL-related dependencies."""
    text_lower = text.lower()
    for pattern in POSTGRES_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return True
    return False

def analyze_python_dependencies(file_path: Path) -> List[str]:
    """Analyze Python dependency files for PostgreSQL packages."""
    postgres_deps = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        # Check pyproject.toml
        if file_path.name == 'pyproject.toml':
            # Look in dependencies and optional-dependencies
            for line in content.split('\n'):
                if is_postgres_dependency(line):
                    # Extract package name
                    match = re.search(r'["\']([^"\']*postgres[^"\']*)["\']', line, re.IGNORECASE)
                    if match:
                        postgres_deps.append(match.group(1))
                    elif 'postgres' in line.lower() or 'psycopg' in line.lower():
                        # Try to extract from the line
                        parts = line.split('=')
                        if len(parts) > 0:
                            dep = parts[0].strip().strip('"').strip("'")
                            if dep:
                                postgres_deps.append(dep)
        
        # Check requirements.txt
        elif file_path.name == 'requirements.txt':
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    if is_postgres_dependency(line):
                        # Extract package name (before == or other version specifiers)
                        dep = re.split(r'[=<>!]', line)[0].strip()
                        postgres_deps.append(dep)
        
        # Check poetry.lock and uv.lock (JSON format)
        elif file_path.name in ['poetry.lock', 'uv.lock']:
            try:
                data = json.loads(content)
                # Search through the JSON structure
                json_str = json.dumps(data)
                if is_postgres_dependency(json_str):
                    # Try to find specific package names
                    if isinstance(data, dict):
                        # Check packages or dependencies
                        for key in ['package', 'dependencies', 'packages']:
                            if key in data:
                                items = data[key] if isinstance(data[key], list) else [data[key]]
                                for item in items:
                                    if isinstance(item, dict):
                                        name = item.get('name', '')
                                        if is_postgres_dependency(name):
                                            postgres_deps.append(name)
            except json.JSONDecodeError:
                # If not valid JSON, search as text
                if is_postgres_dependency(content):
                    postgres_deps.append('postgres-related')
    
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
    
    return list(set(postgres_deps))

def analyze_go_dependencies(file_path: Path) -> List[str]:
    """Analyze Go dependency files for PostgreSQL packages."""
    postgres_deps = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        for line in content.split('\n'):
            if is_postgres_dependency(line):
                # Extract module path
                match = re.search(r'([^\s]+postgres[^\s]*)', line, re.IGNORECASE)
                if match:
                    postgres_deps.append(match.group(1))
                else:
                    # Try to extract from require or replace statements
                    parts = line.split()
                    for part in parts:
                        if is_postgres_dependency(part):
                            postgres_deps.append(part)
    
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
    
    return list(set(postgres_deps))

def analyze_rust_dependencies(file_path: Path) -> List[str]:
    """Analyze Rust dependency files for PostgreSQL packages."""
    postgres_deps = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        # Check Cargo.toml
        if file_path.name == 'Cargo.toml':
            in_deps = False
            for line in content.split('\n'):
                line_lower = line.lower()
                if '[dependencies]' in line_lower or '[dev-dependencies]' in line_lower:
                    in_deps = True
                    continue
                if line.strip().startswith('[') and in_deps:
                    in_deps = False
                
                if in_deps and is_postgres_dependency(line):
                    # Extract crate name
                    match = re.search(r'([a-z0-9_-]*postgres[a-z0-9_-]*)', line, re.IGNORECASE)
                    if match:
                        postgres_deps.append(match.group(1))
                    else:
                        # Try to extract from = "version" format
                        parts = line.split('=')
                        if len(parts) > 0:
                            dep = parts[0].strip().strip('"').strip("'")
                            if dep and is_postgres_dependency(dep):
                                postgres_deps.append(dep)
        
        # Check Cargo.lock (TOML format)
        elif file_path.name == 'Cargo.lock':
            if is_postgres_dependency(content):
                # Try to extract package names
                matches = re.findall(r'name\s*=\s*"([^"]*postgres[^"]*)"', content, re.IGNORECASE)
                postgres_deps.extend(matches)
    
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
    
    return list(set(postgres_deps))

def analyze_nodejs_dependencies(file_path: Path) -> List[str]:
    """Analyze Node.js dependency files for PostgreSQL packages."""
    postgres_deps = []
    
    try:
        if file_path.name == 'package.json':
            data = json.loads(file_path.read_text(encoding='utf-8', errors='ignore'))
            
            # Check dependencies, devDependencies, peerDependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                if dep_type in data:
                    for dep_name, version in data[dep_type].items():
                        if is_postgres_dependency(dep_name):
                            postgres_deps.append(dep_name)
        
        elif file_path.name in ['package-lock.json', 'pnpm-lock.yaml', 'yarn.lock']:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            if is_postgres_dependency(content):
                # Try to extract package names
                if file_path.name == 'package-lock.json':
                    try:
                        data = json.loads(content)
                        json_str = json.dumps(data)
                        # Search for postgres packages
                        matches = re.findall(r'"([^"]*postgres[^"]*)"', json_str, re.IGNORECASE)
                        postgres_deps.extend(matches)
                    except json.JSONDecodeError:
                        pass
                else:
                    # For pnpm-lock.yaml and yarn.lock, search as text
                    matches = re.findall(r'([a-z0-9_-]*postgres[a-z0-9_-]*)', content, re.IGNORECASE)
                    postgres_deps.extend(matches)
    
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
    
    return list(set(postgres_deps))

def analyze_dockerfile(file_path: Path) -> List[str]:
    """Analyze Dockerfile for PostgreSQL installations."""
    postgres_refs = []
    
    try:
        content = file_path.read_text(encoding='utf-8', errors='ignore')
        
        if is_postgres_dependency(content):
            # Look for specific PostgreSQL references
            patterns = [
                r'postgresql[^\s]*',
                r'psycopg[23]?',
                r'libpq',
                r'postgres-client',
            ]
            for pattern in patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                postgres_refs.extend(matches)
    
    except Exception as e:
        print(f"Error reading {file_path}: {e}", file=sys.stderr)
    
    return list(set(postgres_refs))

def analyze_project(result: Dict) -> Dict:
    """Analyze a single project for PostgreSQL dependencies."""
    repo_path = result.get('repo_path')
    if not repo_path or not Path(repo_path).exists():
        return {
            'has_postgres': False,
            'dependencies': {},
            'dockerfiles': [],
            'note': 'Repository not found locally'
        }
    
    repo_path_obj = Path(repo_path)
    analysis = {
        'has_postgres': False,
        'dependencies': defaultdict(list),
        'dockerfiles': [],
        'languages': []
    }
    
    # Analyze dependency files
    deps = result.get('dependencies', {})
    
    for lang, files in deps.items():
        if lang not in analysis['languages']:
            analysis['languages'].append(lang)
        
        for file_rel_path in files:
            # Handle relative paths from repo root
            file_path = repo_path_obj / file_rel_path.replace(f"{result.get('repo', '')}/", "")
            
            if not file_path.exists():
                # Try alternative path
                file_path = Path(file_path)
                if not file_path.exists():
                    continue
            
            postgres_deps = []
            
            if lang == 'python':
                postgres_deps = analyze_python_dependencies(file_path)
            elif lang == 'go':
                postgres_deps = analyze_go_dependencies(file_path)
            elif lang == 'rust':
                postgres_deps = analyze_rust_dependencies(file_path)
            elif lang == 'nodejs':
                postgres_deps = analyze_nodejs_dependencies(file_path)
            
            if postgres_deps:
                analysis['has_postgres'] = True
                analysis['dependencies'][lang].extend(postgres_deps)
                analysis['dependencies'][lang] = list(set(analysis['dependencies'][lang]))
    
    # Analyze Dockerfiles
    dockerfiles = result.get('dockerfiles', [])
    for dockerfile_rel_path in dockerfiles:
        dockerfile_path = repo_path_obj / dockerfile_rel_path.replace(f"{result.get('repo', '')}/", "")
        
        if not dockerfile_path.exists():
            # Try alternative path
            dockerfile_path = Path(dockerfile_path)
            if not dockerfile_path.exists():
                continue
        
        postgres_refs = analyze_dockerfile(dockerfile_path)
        if postgres_refs:
            analysis['has_postgres'] = True
            analysis['dockerfiles'].append({
                'file': dockerfile_rel_path,
                'references': postgres_refs
            })
    
    return analysis

def main():
    """Main analysis function."""
    # Try multiple possible locations for image-source-analysis.json
    script_dir = Path(__file__).parent
    support_dir = script_dir.parent.parent  # ../.. from postgres-dependency-scanner
    possible_locations = [
        support_dir / 'scan-results' / 'postgres-analysis' / 'image-source-analysis.json',  # Default location
        script_dir / 'image-source-analysis.json',  # Same directory as script (fallback)
        Path('scan-results/postgres-analysis/image-source-analysis.json'),  # Relative to current directory (fallback)
    ]
    
    analysis_file = None
    for location in possible_locations:
        if location.exists():
            analysis_file = location
            break
    
    if not analysis_file:
        print(f"Error: image-source-analysis.json not found in any of these locations:", file=sys.stderr)
        for loc in possible_locations:
            print(f"  - {loc}", file=sys.stderr)
        sys.exit(1)
    
    print(f"Using image-source-analysis.json from: {analysis_file}", file=sys.stderr)
    
    with open(analysis_file, 'r') as f:
        data = json.load(f)
    
    results = data.get('results', [])
    
    # Filter to only non-public images with repositories
    projects_to_analyze = [
        r for r in results 
        if not r.get('is_public', False) and r.get('repo_path') and r.get('status') == 'found'
    ]
    
    print(f"Analyzing {len(projects_to_analyze)} projects for PostgreSQL dependencies...\n")
    
    postgres_projects = []
    no_postgres_projects = []
    
    for result in projects_to_analyze:
        image = result.get('image', 'unknown')
        repo = result.get('repo', 'unknown')
        
        print(f"Analyzing {repo} ({image})...", end=' ', flush=True)
        
        analysis = analyze_project(result)
        
        if analysis.get('has_postgres'):
            print("✓ PostgreSQL dependencies found")
            postgres_projects.append({
                'image': image,
                'repo': repo,
                'repo_path': result.get('repo_path'),
                'git_remote_url': result.get('git_remote_url'),
                'analysis': analysis,
                'evidence': result.get('evidence', {})
            })
        else:
            print("✗ No PostgreSQL dependencies")
            no_postgres_projects.append({
                'image': image,
                'repo': repo,
                'git_remote_url': result.get('git_remote_url')
            })
    
    # Generate report
    report = {
        'summary': {
            'total_projects': len(projects_to_analyze),
            'with_postgres': len(postgres_projects),
            'without_postgres': len(no_postgres_projects),
            'migration_effort': {
                'high': 0,
                'medium': 0,
                'low': 0
            }
        },
        'projects_with_postgres': postgres_projects,
        'projects_without_postgres': [p['repo'] for p in no_postgres_projects]
    }
    
    # Categorize migration effort
    for project in postgres_projects:
        analysis = project['analysis']
        lang_count = len(analysis.get('languages', []))
        dep_count = sum(len(deps) for deps in analysis.get('dependencies', {}).values())
        dockerfile_count = len(analysis.get('dockerfiles', []))
        
        # Simple heuristic: more languages/dependencies = higher effort
        if lang_count > 1 or dep_count > 3 or dockerfile_count > 2:
            report['summary']['migration_effort']['high'] += 1
        elif dep_count > 1 or dockerfile_count > 0:
            report['summary']['migration_effort']['medium'] += 1
        else:
            report['summary']['migration_effort']['low'] += 1
    
    # Output report (use scan-results/postgres-analysis directory)
    output_dir = support_dir / 'scan-results' / 'postgres-analysis'
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / 'postgres-dependency-analysis.json'
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n{'='*80}")
    print("POSTGRESQL DEPENDENCY ANALYSIS REPORT")
    print(f"{'='*80}\n")
    print(f"Total projects analyzed: {report['summary']['total_projects']}")
    print(f"Projects with PostgreSQL dependencies: {report['summary']['with_postgres']}")
    print(f"Projects without PostgreSQL dependencies: {report['summary']['without_postgres']}\n")
    
    print("Migration Effort Breakdown:")
    print(f"  High effort: {report['summary']['migration_effort']['high']} projects")
    print(f"  Medium effort: {report['summary']['migration_effort']['medium']} projects")
    print(f"  Low effort: {report['summary']['migration_effort']['low']} projects\n")
    
    if postgres_projects:
        print(f"\n{'='*80}")
        print("PROJECTS WITH POSTGRESQL DEPENDENCIES:")
        print(f"{'='*80}\n")
        
        for project in postgres_projects:
            print(f"Repository: {project['repo']}")
            print(f"Image: {project['image']}")
            print(f"Languages: {', '.join(project['analysis'].get('languages', []))}")
            
            deps = project['analysis'].get('dependencies', {})
            if deps:
                print("Dependencies:")
                for lang, packages in deps.items():
                    print(f"  {lang}: {', '.join(packages)}")
            
            dockerfiles = project['analysis'].get('dockerfiles', [])
            if dockerfiles:
                print("Dockerfile references:")
                for df in dockerfiles:
                    print(f"  {df['file']}: {', '.join(df['references'])}")
            
            print()
    
    print(f"\nDetailed report saved to: {output_file}")

if __name__ == '__main__':
    main()

