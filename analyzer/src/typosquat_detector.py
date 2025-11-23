#!/usr/bin/env python3
"""
Typosquat Detection Engine for PackageInferno
Based on dnstwist algorithms adapted for npm package names
"""
import re
import json
from pathlib import Path
from collections import defaultdict

class TyposquatDetector:
    """
    Detects typosquatting in npm package names using multiple algorithms
    Inspired by dnstwist and opensquat methodologies
    """
    
    def __init__(self):
        # Popular npm packages to protect (top 1000+ packages)
        self.popular_packages = self._load_popular_packages()
        
        # Common typosquatting patterns
        self.substitutions = {
            'o': ['0', 'ο', 'о'],  # Latin o, digit 0, Greek omicron, Cyrillic o
            'a': ['а', 'α'],       # Latin a, Cyrillic a, Greek alpha
            'e': ['е', 'ε', '3'],  # Latin e, Cyrillic e, Greek epsilon, digit 3
            'i': ['і', 'ι', 'l', '1'],  # Latin i, Cyrillic i, Greek iota, l, 1
            'u': ['υ', 'ս'],       # Greek upsilon, Armenian u
            'p': ['р', 'ρ'],       # Cyrillic p, Greek rho
            'c': ['с', 'ϲ'],       # Cyrillic c, Greek c
            'x': ['х', 'χ'],       # Cyrillic x, Greek chi
            'y': ['у', 'γ'],       # Cyrillic y, Greek gamma
            'n': ['п'],            # Cyrillic n
            'm': ['м'],            # Cyrillic m
            'h': ['һ'],            # Cyrillic h
            'k': ['к'],            # Cyrillic k
            'r': ['г'],            # Cyrillic r
            'l': ['ӏ', '1', 'i'],  # Cyrillic l, digit 1, i
            's': ['ѕ'],            # Cyrillic s
            't': ['т'],            # Cyrillic t
            'v': ['ν'],            # Greek nu
            'w': ['ω'],            # Greek omega
        }
    
    def _load_popular_packages(self):
        """Load list of popular npm packages to protect against typosquats"""
        # Top npm packages (could be loaded from external source)
        popular = [
            # Core packages
            'lodash', 'express', 'react', 'vue', 'angular', 'typescript',
            'webpack', 'babel', 'eslint', 'prettier', 'axios', 'moment',
            'jquery', 'bootstrap', 'commander', 'chalk', 'debug', 'fs-extra',
            
            # Scoped packages  
            '@angular/core', '@angular/common', '@babel/core', '@types/node',
            '@typescript-eslint/parser', '@vue/cli', '@nuxt/core',
            
            # Security/crypto related
            'bcrypt', 'jsonwebtoken', 'passport', 'crypto-js', 'uuid',
            
            # AI/ML related (high value targets)
            '@anthropic-ai/claude-code', '@openai/api', 'openai',
            '@huggingface/transformers', 'tensorflow', 'pytorch',
            
            # Popular CLIs
            'create-react-app', 'create-vue', '@vue/cli', '@angular/cli',
            'serverless', 'aws-cli', 'firebase-tools'
        ]
        
        # Add variations with different scopes
        expanded = []
        for pkg in popular:
            expanded.append(pkg)
            if not pkg.startswith('@'):
                # Add common scope variations
                expanded.extend([
                    f'@{pkg}/core',
                    f'@{pkg}/cli', 
                    f'@types/{pkg}',
                    f'@babel/{pkg}',
                    f'@webpack/{pkg}'
                ])
        
        return set(expanded)
    
    def generate_permutations(self, domain):
        """Generate typosquat permutations using dnstwist-inspired algorithms"""
        permutations = set()
        
        # Remove scope for processing
        if domain.startswith('@'):
            scope_match = re.match(r'@([^/]+)/(.+)', domain)
            if scope_match:
                scope, name = scope_match.groups()
                base_domain = name
                has_scope = True
            else:
                base_domain = domain[1:]  # Remove @
                scope = None
                has_scope = False
        else:
            base_domain = domain
            has_scope = False
            scope = None
        
        # 1. Character omission
        for i in range(len(base_domain)):
            permutations.add(base_domain[:i] + base_domain[i+1:])
        
        # 2. Character repetition  
        for i in range(len(base_domain)):
            permutations.add(base_domain[:i] + base_domain[i] + base_domain[i:])
        
        # 3. Character replacement
        for i, char in enumerate(base_domain):
            if char.lower() in self.substitutions:
                for replacement in self.substitutions[char.lower()]:
                    permutations.add(base_domain[:i] + replacement + base_domain[i+1:])
        
        # 4. Adjacent character swap
        for i in range(len(base_domain) - 1):
            permutations.add(
                base_domain[:i] + 
                base_domain[i+1] + 
                base_domain[i] + 
                base_domain[i+2:]
            )
        
        # 5. Character insertion (common typos)
        common_inserts = 'abcdefghijklmnopqrstuvwxyz0123456789-_'
        for i in range(len(base_domain) + 1):
            for char in common_inserts:
                permutations.add(base_domain[:i] + char + base_domain[i:])
        
        # 6. Subdomain variations (for scoped packages)
        subdomain_variations = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app'
        ]
        
        # 7. TLD variations (package scope variations)
        scope_variations = [
            'official', 'org', 'team', 'dev', 'community', 'js', 'ts',
            'core', 'cli', 'api', 'sdk', 'lib', 'utils', 'tools'
        ]
        
        # Apply scope variations
        final_permutations = set()
        for perm in permutations:
            if len(perm) > 1:  # Skip very short names
                if has_scope:
                    # Original scope
                    final_permutations.add(f'@{scope}/{perm}')
                    # Different scopes
                    for new_scope in scope_variations:
                        final_permutations.add(f'@{new_scope}/{perm}')
                        final_permutations.add(f'@{perm}/{new_scope}')
                else:
                    # No scope
                    final_permutations.add(perm)
                    # Add scope variations
                    for scope_var in scope_variations:
                        final_permutations.add(f'@{scope_var}/{perm}')
        
        # Remove original domain and very short names
        final_permutations.discard(domain)
        final_permutations = {p for p in final_permutations if len(p) > 2}
        
        return final_permutations
    
    def detect_typosquats_in_packages(self, package_list):
        """Detect typosquats in a list of package names"""
        results = []
        
        for package_name in package_list:
            for popular in self.popular_packages:
                # Check if this package might be typosquatting a popular one
                if self._is_potential_typosquat(package_name, popular):
                    similarity_score = self._calculate_similarity(package_name, popular)
                    results.append({
                        'suspicious_package': package_name,
                        'legitimate_package': popular,
                        'similarity_score': similarity_score,
                        'typosquat_type': self._classify_typosquat_type(package_name, popular)
                    })
        
        return results
    
    def _is_potential_typosquat(self, suspicious, legitimate):
        """Check if suspicious package might be typosquatting legitimate one"""
        # Remove scopes for comparison
        sus_name = self._extract_package_name(suspicious)
        leg_name = self._extract_package_name(legitimate)
        
        # Skip if identical
        if sus_name == leg_name:
            return False
        
        # Check Levenshtein distance
        distance = self._levenshtein_distance(sus_name, leg_name)
        
        # Consider it a potential typosquat if:
        # - Edit distance <= 3 for names > 6 chars
        # - Edit distance <= 2 for names 4-6 chars  
        # - Edit distance <= 1 for names < 4 chars
        if len(leg_name) > 6 and distance <= 3:
            return True
        elif len(leg_name) >= 4 and distance <= 2:
            return True
        elif len(leg_name) < 4 and distance <= 1:
            return True
        
        # Check for character substitution attacks
        if self._has_character_substitution(sus_name, leg_name):
            return True
        
        # Check for scope hijacking (@legit/package vs @fake/package)
        if suspicious.startswith('@') and legitimate.startswith('@'):
            sus_scope = suspicious.split('/')[0]
            leg_scope = legitimate.split('/')[0]
            if sus_scope != leg_scope and sus_name == leg_name:
                return True
        
        return False
    
    def _extract_package_name(self, package):
        """Extract package name without scope"""
        if package.startswith('@'):
            parts = package.split('/')
            return parts[1] if len(parts) > 1 else package[1:]
        return package
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _has_character_substitution(self, suspicious, legitimate):
        """Check for Unicode character substitution attacks"""
        if len(suspicious) != len(legitimate):
            return False
        
        substitution_count = 0
        for i, (s_char, l_char) in enumerate(zip(suspicious, legitimate)):
            if s_char != l_char:
                substitution_count += 1
                # Check if it's a known substitution
                if l_char.lower() in self.substitutions:
                    if s_char in self.substitutions[l_char.lower()]:
                        continue  # Valid substitution
                # If not a known substitution, might not be typosquat
                if substitution_count > 2:  # Too many differences
                    return False
        
        return substitution_count > 0 and substitution_count <= 2
    
    def _calculate_similarity(self, s1, s2):
        """Calculate similarity percentage"""
        distance = self._levenshtein_distance(s1.lower(), s2.lower())
        max_len = max(len(s1), len(s2))
        return (1 - distance / max_len) * 100 if max_len > 0 else 0
    
    def _classify_typosquat_type(self, suspicious, legitimate):
        """Classify the type of typosquatting attack"""
        sus_name = self._extract_package_name(suspicious)
        leg_name = self._extract_package_name(legitimate)
        
        if len(sus_name) == len(leg_name):
            if self._has_character_substitution(sus_name, leg_name):
                return 'character_substitution'
            else:
                return 'character_swap'
        elif len(sus_name) == len(leg_name) - 1:
            return 'character_omission'
        elif len(sus_name) == len(leg_name) + 1:
            return 'character_insertion'
        else:
            return 'multiple_changes'

# SQL query for database-level typosquat detection
TYPOSQUAT_DETECTION_SQL = """
-- Typosquat Detection Query for PackageInferno Database
-- Finds packages with suspicious similarity to popular packages

WITH popular_targets AS (
    -- Define high-value packages that are commonly typosquatted
    VALUES 
        ('lodash'),
        ('express'), 
        ('react'),
        ('vue'),
        ('@angular/core'),
        ('@angular/common'),
        ('typescript'),
        ('webpack'),
        ('@babel/core'),
        ('eslint'),
        ('axios'),
        ('moment'),
        ('jquery'),
        ('bootstrap'),
        ('commander'),
        ('chalk'),
        ('debug'),
        ('@anthropic-ai/claude-code'),
        ('@openai/api'),
        ('openai'),
        ('create-react-app'),
        ('@vue/cli'),
        ('serverless'),
        ('firebase-tools')
),
potential_typosquats AS (
    SELECT DISTINCT
        p.name as suspicious_package,
        pt.column1 as target_package,
        -- Calculate different similarity metrics
        CASE 
            WHEN p.name LIKE CONCAT('%', SUBSTRING(pt.column1 FROM 2), '%') THEN 'substring_match'
            WHEN p.name LIKE CONCAT(SUBSTRING(pt.column1 FROM 1 FOR LENGTH(pt.column1)-1), '%') THEN 'prefix_truncation'
            WHEN REPLACE(p.name, '0', 'o') = pt.column1 THEN 'zero_to_o'
            WHEN REPLACE(p.name, 'l', 'i') = pt.column1 THEN 'l_to_i'
            WHEN REPLACE(p.name, '1', 'i') = pt.column1 THEN 'one_to_i'
            WHEN REPLACE(p.name, '3', 'e') = pt.column1 THEN 'three_to_e'
            ELSE 'other'
        END as attack_type
    FROM packages p
    CROSS JOIN popular_targets pt
    WHERE p.name != pt.column1
      AND (
          -- Character substitution attacks
          REPLACE(p.name, '0', 'o') = pt.column1 OR
          REPLACE(p.name, 'l', 'i') = pt.column1 OR
          REPLACE(p.name, '1', 'i') = pt.column1 OR
          REPLACE(p.name, '3', 'e') = pt.column1 OR
          
          -- Substring/prefix attacks
          p.name LIKE CONCAT('%', SUBSTRING(pt.column1 FROM 2), '%') OR
          p.name LIKE CONCAT(SUBSTRING(pt.column1 FROM 1 FOR LENGTH(pt.column1)-1), '%') OR
          
          -- Scope hijacking (@fake/package vs @real/package)
          (p.name LIKE CONCAT('@%/', SUBSTRING(pt.column1 FROM 2)) AND pt.column1 NOT LIKE '@%') OR
          
          -- Similar length with 1-2 character differences
          (ABS(LENGTH(p.name) - LENGTH(pt.column1)) <= 2 AND
           p.name SIMILAR TO CONCAT(SUBSTRING(pt.column1 FROM 1 FOR 3), '%'))
      )
)
SELECT 
    ts.suspicious_package,
    ts.target_package,
    ts.attack_type,
    COUNT(f.id) as total_findings,
    COUNT(CASE WHEN f.severity = 'high' THEN 1 END) as high_severity_findings,
    MAX(s.score) as max_score,
    MAX(s.label) as threat_label,
    -- Package metadata
    MAX(v.analyzed_at) as last_analyzed
FROM potential_typosquats ts
JOIN packages p ON p.name = ts.suspicious_package
JOIN versions v ON v.package_id = p.id
LEFT JOIN findings f ON f.version_id = v.id
LEFT JOIN scores s ON s.version_id = v.id
GROUP BY ts.suspicious_package, ts.target_package, ts.attack_type
-- Only show packages with actual threats
HAVING MAX(s.score) > 100 OR COUNT(CASE WHEN f.severity = 'high' THEN 1 END) > 5
ORDER BY MAX(s.score) DESC, COUNT(f.id) DESC
LIMIT 100;
"""

# Mixed-case detection (based on nice-registry research)
MIXED_CASE_DETECTION_SQL = """
-- Detect packages using mixed case for deception
-- Based on nice-registry/mixed-case-package-names research

SELECT 
    p.name,
    COUNT(f.id) as findings,
    MAX(s.score) as score,
    MAX(s.label) as label,
    CASE 
        WHEN p.name ~ '[A-Z].*[a-z].*[A-Z]' THEN 'camelCase_mixed'
        WHEN p.name ~ '^[a-z]+[A-Z]' THEN 'starts_lower_has_upper'
        WHEN p.name ~ '[A-Z]{2,}' THEN 'multiple_uppercase'
        ELSE 'other_mixed_case'
    END as case_pattern
FROM packages p
JOIN versions v ON v.package_id = p.id
LEFT JOIN findings f ON f.version_id = v.id
LEFT JOIN scores s ON s.version_id = v.id
WHERE p.name ~ '[A-Z]'  -- Contains uppercase
  AND p.name ~ '[a-z]'  -- Contains lowercase
  AND p.name NOT LIKE '@%'  -- Exclude scoped packages (often have mixed case)
GROUP BY p.name
HAVING MAX(s.score) > 50
ORDER BY MAX(s.score) DESC
LIMIT 50;
"""

if __name__ == '__main__':
    # Test the detector
    detector = TyposquatDetector()
    
    # Test with known malicious package
    test_packages = [
        '@chatgptclaude_club/claude-code',
        'lodahs',  # lodash typo
        'expres',  # express typo
        'recat',   # react typo
    ]
    
    print("🔍 TESTING TYPOSQUAT DETECTOR:")
    print("=" * 60)
    
    for package in test_packages:
        results = detector.detect_typosquats_in_packages([package])
        for result in results:
            print(f"📦 {result['suspicious_package']}")
            print(f"   Mimics: {result['legitimate_package']}")
            print(f"   Type: {result['typosquat_type']}")
            print(f"   Similarity: {result['similarity_score']:.1f}%")
            print()

