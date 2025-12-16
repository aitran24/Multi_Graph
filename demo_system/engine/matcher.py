"""
Template Matcher - Graph Matching Algorithm
===========================================
Matches live provenance graphs against detection templates.
Uses BOTH graph similarity AND behavioral signatures.
"""

import json
import networkx as nx
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from networkx.algorithms import isomorphism
import re


# Behavioral signatures for quick detection
BEHAVIORAL_SIGNATURES = {
    'T1059.001': {
        'name': 'PowerShell Command & Scripting',
        'patterns': [
            r'powershell\.exe.*-enc',
            r'powershell\.exe.*-encodedcommand',
            r'powershell\.exe.*-nop.*-w\s*hidden',
            r'powershell\.exe.*-executionpolicy\s*bypass',
            r'powershell\.exe.*invoke-expression',
            r'powershell\.exe.*iex\s*\(',
            r'powershell\.exe.*downloadstring',
            r'powershell\.exe.*-sta.*-noni',
        ],
        'processes': ['powershell.exe'],
    },
    'T1003.001': {
        'name': 'LSASS Memory Dump',
        'patterns': [
            r'procdump.*-ma.*lsass',
            r'mimikatz',
            r'sekurlsa::logonpasswords',
            r'comsvcs\.dll.*minidump',
        ],
        'processes': ['procdump.exe', 'procdump64.exe', 'mimikatz.exe'],
        'target_processes': ['lsass.exe'],
    },
    'T1112': {
        'name': 'Registry Modification',
        'patterns': [
            r'reg\.exe.*add',
            r'reg\.exe.*delete',
            r'set-itemproperty.*registry',
            r'new-itemproperty.*registry',
        ],
        'registry_paths': [
            r'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
            r'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
        ],
    },
    'T1547.001': {
        'name': 'Registry Run Keys Persistence',
        'patterns': [
            r'reg.*add.*\\run',
            r'set-itemproperty.*currentversion\\run',
        ],
        'registry_paths': [
            r'CurrentVersion\\Run',
            r'CurrentVersion\\RunOnce',
        ],
    },
    'T1218.011': {
        'name': 'Rundll32 Proxy Execution',
        'patterns': [
            r'rundll32\.exe.*javascript',
            r'rundll32\.exe.*vbscript',
            r'rundll32\.exe.*shell32',
        ],
        'processes': ['rundll32.exe'],
    },
}


class TemplateMatcher:
    """
    Match live graphs against attack technique templates.
    """
    
    def __init__(self, knowledge_base_dir: str):
        """
        Initialize matcher with templates.
        
        Args:
            knowledge_base_dir: Path to folder containing v3.0 JSON templates
        """
        self.knowledge_base_dir = Path(knowledge_base_dir)
        self.templates = {}
        self.load_templates()
    
    def load_templates(self):
        """Load all detection templates from knowledge base."""
        print(f"[MATCHER] Loading templates from {self.knowledge_base_dir}")
        
        for json_file in self.knowledge_base_dir.glob("*.json"):
            technique_id = json_file.stem.replace('_graph_v3.0', '')
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                # Convert to NetworkX graph
                G = nx.DiGraph()
                
                for node in data.get('nodes', []):
                    # Extract properties and add type separately to avoid conflict
                    props = node.get('properties', {}).copy()
                    props['type'] = node.get('type')
                    G.add_node(node['id'], **props)
                
                for edge in data.get('edges', []):
                    G.add_edge(edge['source'], edge['target'],
                              operations=edge.get('operations', []))
                
                self.templates[technique_id] = {
                    'graph': G,
                    'name': data.get('metadata', {}).get('technique_name', technique_id),
                    'metadata': data.get('metadata', {})
                }
                
                print(f"  ✓ Loaded {technique_id}: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
            
            except Exception as e:
                print(f"  ✗ Failed to load {technique_id}: {e}")
        
        print(f"[MATCHER] ✅ Loaded {len(self.templates)} templates\n")
    
    def match_graph(self, live_graph: nx.DiGraph, threshold=0.5) -> List[Dict]:
        """
        Match live graph against all templates using HYBRID approach:
        1. Behavioral signature matching (fast, catches common patterns)
        2. Graph similarity matching (comprehensive)
        
        Args:
            live_graph: Graph built from recent events
            threshold: Minimum similarity score (0-1)
        
        Returns:
            List of matches with scores
        """
        matches = []
        
        # Extract all command lines and process names from live graph
        command_lines = []
        process_names = []
        registry_paths = []
        
        for node_id, data in live_graph.nodes(data=True):
            cmd = data.get('command_line', '') or data.get('commandLine', '') or data.get('CommandLine', '') or ''
            img = data.get('image', '') or data.get('Image', '') or data.get('label', '') or ''
            target = data.get('target_object', '') or data.get('TargetObject', '') or data.get('key', '') or ''
            
            if cmd:
                command_lines.append(cmd.lower())
            if img:
                process_names.append(img.lower().split('\\')[-1])
            if target:
                registry_paths.append(target.lower())
        
        # Phase 1: Behavioral Signature Matching
        for technique_id, sig in BEHAVIORAL_SIGNATURES.items():
            score = 0.0
            matched_patterns = []
            
            # Check command line patterns
            for pattern in sig.get('patterns', []):
                for cmd in command_lines:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        score += 0.3
                        matched_patterns.append(f"Pattern: {pattern[:30]}...")
                        break
            
            # Check process names
            for proc in sig.get('processes', []):
                if proc.lower() in process_names:
                    score += 0.2
                    matched_patterns.append(f"Process: {proc}")
            
            # Check registry paths
            for reg_pattern in sig.get('registry_paths', []):
                for reg in registry_paths:
                    if re.search(reg_pattern, reg, re.IGNORECASE):
                        score += 0.3
                        matched_patterns.append(f"Registry: {reg_pattern[:30]}...")
                        break
            
            if score >= threshold:
                matches.append({
                    'technique_id': technique_id,
                    'technique_name': sig['name'],
                    'confidence': min(score, 1.0),
                    'match_type': 'behavioral',
                    'matched_patterns': matched_patterns,
                    'template_nodes': self.templates.get(technique_id, {}).get('graph', nx.DiGraph()).number_of_nodes(),
                    'template_edges': self.templates.get(technique_id, {}).get('graph', nx.DiGraph()).number_of_edges(),
                })
        
        # Phase 2: Graph Similarity Matching (for templates without behavioral signatures)
        for technique_id, template_data in self.templates.items():
            # Skip if already matched by behavioral
            if any(m['technique_id'] == technique_id for m in matches):
                continue
            
            template_graph = template_data['graph']
            
            # Calculate similarity
            score = self.calculate_similarity(live_graph, template_graph)
            
            if score >= threshold:
                matches.append({
                    'technique_id': technique_id,
                    'technique_name': template_data.get('name', technique_id),
                    'confidence': score,
                    'match_type': 'graph_similarity',
                    'matched_patterns': [],
                    'template_nodes': template_graph.number_of_nodes(),
                    'template_edges': template_graph.number_of_edges(),
                })
        
        # Sort by confidence (highest first)
        matches.sort(key=lambda x: x['confidence'], reverse=True)
        
        return matches
    
    def calculate_similarity(self, graph1: nx.DiGraph, graph2: nx.DiGraph) -> float:
        """
        Calculate similarity between two graphs.
        
        Uses multiple metrics:
        1. Subgraph isomorphism (exact match)
        2. Node/edge overlap
        3. Structural similarity
        
        Returns:
            Similarity score (0-1)
        """
        if graph1.number_of_nodes() == 0 or graph2.number_of_nodes() == 0:
            return 0.0
        
        # Metric 1: Subgraph Isomorphism (Check if template is subgraph of live)
        # Template should be smaller or equal
        if graph2.number_of_nodes() <= graph1.number_of_nodes():
            # Check if graph2 (template) is subgraph of graph1 (live)
            matcher = isomorphism.DiGraphMatcher(
                graph1, graph2,
                node_match=self.node_matcher
            )
            
            if matcher.subgraph_is_isomorphic():
                return 1.0  # Perfect match
        
        # Metric 2: Node Type Overlap
        g1_types = [data.get('type') for _, data in graph1.nodes(data=True)]
        g2_types = [data.get('type') for _, data in graph2.nodes(data=True)]
        
        type_overlap = len(set(g1_types) & set(g2_types)) / max(len(set(g1_types)), len(set(g2_types)))
        
        # Metric 3: Edge Overlap (approximate)
        g1_edges = set(graph1.edges())
        g2_edges = set(graph2.edges())
        
        # Simplified edge matching (ignore node IDs, just count)
        edge_ratio = min(len(g1_edges), len(g2_edges)) / max(len(g1_edges), len(g2_edges), 1)
        
        # Metric 4: Structural Similarity (node/edge ratio)
        g1_ratio = graph1.number_of_edges() / max(graph1.number_of_nodes(), 1)
        g2_ratio = graph2.number_of_edges() / max(graph2.number_of_nodes(), 1)
        struct_sim = 1 - abs(g1_ratio - g2_ratio) / max(g1_ratio, g2_ratio, 1)
        
        # Combined score (weighted average)
        score = (
            type_overlap * 0.4 +
            edge_ratio * 0.3 +
            struct_sim * 0.3
        )
        
        return min(score, 1.0)
    
    @staticmethod
    def node_matcher(node1: Dict, node2: Dict) -> bool:
        """
        Check if two nodes match.
        
        Args:
            node1, node2: Node attribute dictionaries
        
        Returns:
            True if nodes match
        """
        # Must have same type
        if node1.get('type') != node2.get('type'):
            return False
        
        # For Process nodes, match by name
        if node1.get('type') == 'Process':
            label1 = node1.get('label', '').lower()
            label2 = node2.get('label', '').lower()
            return label1 == label2
        
        # For other nodes, type match is enough
        return True


# Example usage
if __name__ == "__main__":
    # Test loading templates
    knowledge_base = "../knowledge_base"
    matcher = TemplateMatcher(knowledge_base)
    
    # Create dummy live graph
    live_graph = nx.DiGraph()
    live_graph.add_node("Process:test", type='Process', label='powershell.exe')
    live_graph.add_node("File:test", type='File', label='test.txt')
    live_graph.add_edge("Process:test", "File:test", operations=['CREATE_FILE'])
    
    # Match
    matches = matcher.match_graph(live_graph, threshold=0.5)
    
    print(f"\nFound {len(matches)} potential matches:")
    for match in matches:
        print(f"  - {match['technique_id']}: {match['confidence']:.2%} confidence")
