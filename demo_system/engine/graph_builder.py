"""
Graph Builder - Construct Provenance Graphs from Events
=======================================================
Builds NetworkX graphs from streaming Sysmon events.
"""

import networkx as nx
from datetime import datetime, timedelta
from typing import Dict, List
import re
from pathlib import Path
import hashlib


class GraphBuilder:
    """
    Build provenance graphs from Sysmon events.
    """
    
    def __init__(self, window_seconds=30):
        """
        Initialize builder.
        
        Args:
            window_seconds: Time window for graph construction
        """
        self.window_seconds = window_seconds
        self.events = []
        self.graph = nx.DiGraph()
    
    def add_event(self, event: Dict):
        """Add event to buffer.

        Accepts two formats:
        - Full Sysmon-style: { 'EventID': int, 'Data': { ... } }
        - Compact collector-style: { 'event_id', 'timestamp', 'image', 'commandline', 'user', 'target', 'raw_message' }

        This method normalizes compact events into the full format so downstream
        code can rely on `EventID` and `Data` keys.
        """

        # If event already in full Sysmon format, keep as-is
        if not isinstance(event, dict):
            return

        if 'EventID' not in event or 'Data' not in event:
            # Normalize compact fields to Sysmon-like structure
            event_id = event.get('event_id') or event.get('EventID') or event.get('EventId') or 0
            timestamp = event.get('timestamp') or event.get('TimeCreated') or event.get('Timestamp') or ''
            image = event.get('image') or event.get('Image') or ''
            cmdline = event.get('commandline') or event.get('commandLine') or event.get('CommandLine') or ''
            target = event.get('target') or event.get('TargetFilename') or event.get('TargetObject') or ''
            process_guid = event.get('process_guid') or event.get('ProcessGuid') or event.get('processguid')
            parent_guid = event.get('parent_process_guid') or event.get('ParentProcessGuid') or event.get('parentprocessguid') or ''

            # Generate a pseudo ProcessGuid when missing to allow linking
            if not process_guid:
                pseudo = self.hash_content(f"{timestamp}|{image}|{cmdline}")
                process_guid = f"{{{pseudo}}}"

            normalized = {
                'EventID': int(event_id) if (isinstance(event_id, (int, str)) and str(event_id).isdigit()) else event_id,
                'Timestamp': timestamp,
                'Data': {
                    'ProcessGuid': process_guid,
                    'ParentProcessGuid': parent_guid,
                    'Image': image,
                    'CommandLine': cmdline,
                    'TargetFilename': target,
                    'TargetObject': target,
                }
            }

            event = normalized

        self.events.append(event)

        # Keep only recent events in memory
        if len(self.events) > 1000:
            self.events = self.events[-1000:]
    
    def generalize_path(self, path: str) -> str:
        """
        Generalize Windows paths to environment variables.
        (Same as aggregation pipeline)
        """
        if not isinstance(path, str):
            return path
        
        patterns = [
            (r'C:\\Users\\[^\\]+', r'%USERPROFILE%'),
            (r'C:\\Windows', r'%WINDIR%'),
            (r'C:\\ProgramData', r'%PROGRAMDATA%'),
            (r'C:\\Program Files( \(x86\))?', r'%PROGRAMFILES%'),
        ]
        
        for pattern, replacement in patterns:
            path = re.sub(pattern, replacement, path, flags=re.IGNORECASE)
        
        return path
    
    def is_noise_event(self, event: Dict) -> bool:
        """
        Check if event should be filtered as noise.
        """
        data = event.get('Data', {})
        
        # Noise processes
        noise_processes = [
            'svchost.exe', 'conhost.exe', 'chcp.com',
            'taskhostw.exe', 'backgroundtaskhost.exe'
        ]
        
        image = data.get('Image', '').lower()
        for noise in noise_processes:
            if noise in image:
                return True
        
        # Noise files
        noise_patterns = [
            'psscriptpolicytest',
            '.tmp$', '.etl$',
            'desktop.ini'
        ]
        
        target = data.get('TargetFilename', data.get('TargetObject', '')).lower()
        for pattern in noise_patterns:
            if re.search(pattern, target):
                return True
        
        return False
    
    def build_graph(self) -> nx.DiGraph:
        """
        Build graph from recent events.
        
        Returns:
            NetworkX DiGraph
        """
        G = nx.DiGraph()
        
        # Filter noise
        valid_events = [e for e in self.events if not self.is_noise_event(e)]
        
        for event in valid_events:
            event_id = event['EventID']
            data = event.get('Data', {})
            
            # Process Create (Event ID 1)
            if event_id == 1:
                process_guid = data.get('ProcessGuid', '')
                parent_guid = data.get('ParentProcessGuid', '')
                image = data.get('Image', '')
                cmdline = data.get('CommandLine', '')
                
                # Create process node
                if process_guid:
                    proc_key = process_guid[:8]
                    process_id = f"Process:{proc_key}"
                else:
                    process_id = f"Process:{self.hash_content(image + cmdline)}"

                G.add_node(process_id,
                          type='Process',
                          label=Path(image).stem if image else 'unknown',
                          image=self.generalize_path(image),
                          command_line=self.generalize_path(cmdline),
                          guid=process_guid)
                
                # Create edge from parent
                if parent_guid:
                    parent_id = f"Process:{parent_guid[:8]}"
                    if parent_id in G.nodes():
                        G.add_edge(parent_id, process_id, 
                                  operations=['CREATE_PROCESS'])
            
            # File Create (Event ID 11)
            elif event_id == 11:
                process_guid = data.get('ProcessGuid', '')
                target_file = data.get('TargetFilename', '')
                
                if target_file:
                    file_id = f"File:{self.hash_content(target_file)}"
                    G.add_node(file_id,
                              type='File',
                              label=Path(target_file).name,
                              path=self.generalize_path(target_file))
                    
                    # Edge from process to file
                    process_id = f"Process:{process_guid[:8]}" if process_guid else f"Process:{self.hash_content(data.get('Image','') + data.get('CommandLine',''))}"
                    if process_id in G.nodes():
                        G.add_edge(process_id, file_id,
                                  operations=['CREATE_FILE'])
            
            # Registry Set (Event ID 13)
            elif event_id == 13:
                process_guid = data.get('ProcessGuid', '')
                target_object = data.get('TargetObject', '')
                
                if target_object:
                    reg_id = f"Registry:{self.hash_content(target_object)}"
                    G.add_node(reg_id,
                              type='Registry',
                              label=target_object.split('\\')[-1],
                              key=self.generalize_path(target_object))
                    
                    # Edge from process to registry
                    process_id = f"Process:{process_guid[:8]}" if process_guid else f"Process:{self.hash_content(data.get('Image','') + data.get('CommandLine',''))}"
                    if process_id in G.nodes():
                        G.add_edge(process_id, reg_id,
                                  operations=['SET_REGISTRY'])
        
        # Remove isolated nodes
        G.remove_nodes_from(list(nx.isolates(G)))
        
        return G
    
    @staticmethod
    def hash_content(text: str, length=8) -> str:
        """Generate short hash of content."""
        return hashlib.sha256(text.encode()).hexdigest()[:length]


# Example usage
if __name__ == "__main__":
    builder = GraphBuilder(window_seconds=30)
    
    # Simulate events
    test_event = {
        'EventID': 1,
        'Timestamp': datetime.now().isoformat(),
        'Data': {
            'ProcessGuid': '{12345678-1234-1234-1234-123456789ABC}',
            'ParentProcessGuid': '{00000000-0000-0000-0000-000000000000}',
            'Image': 'C:\\Windows\\System32\\cmd.exe',
            'CommandLine': 'cmd.exe /c echo test'
        }
    }
    
    builder.add_event(test_event)
    graph = builder.build_graph()
    
    print(f"Graph: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")
    for node, data in graph.nodes(data=True):
        print(f"  {node}: {data}")
