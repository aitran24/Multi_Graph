# Config-Driven MultiKG Graph Generation System

Professional provenance graph generation system for ATT&CK techniques, inspired by Sigma and ElastAlert architectures.

## Architecture Overview

```
atomic_red_team_data/          # Input: Sysmon logs
├── T1003.001/
│   └── windows-sysmon.log
├── T1003.002/
│   └── windows-sysmon.log
└── ...

configs/                        # Detection rules (JSON)
├── global_whitelist.json      # Shared filtering rules
├── T1003.001.json             # LSASS Memory Dumping
├── T1003.002.json             # SAM Registry
└── ...

output/                         # Generated graphs
├── T1003.001_graph_v2.json
├── T1003.002_graph_v2.json
└── ...
```

## Features

### 1. Config-Driven Detection
- **Maintainable**: Edit JSON configs without touching code
- **Scalable**: Add new technique = add new JSON file
- **Professional**: Follows industry standards (Sigma, ElastAlert)

### 2. Hard Splunk Filtering
- Removes noise from Splunk, CCM, Windows Defender paths
- Filters 10,821+ events across all techniques
- Checks all image fields: Image, SourceImage, TargetImage, ParentImage

### 3. ProcessGuid-Based Node IDs
- **Old**: `Process:4368` (PID only - suffers from PID reuse)
- **New**: `Process:31314CADF2B45FB4` (ProcessGuid from Sysmon)
- **Benefit**: Unique IDs prevent process conflicts

### 4. OSSEM Schema
- Standardized node types: Process, Registry, File, Network
- Relationship types: CREATED, TEMPORAL_RELATED
- Compatible with Neo4j graph database

## Quick Start

### 1. Run All Techniques
```bash
python run_multig.py
```

### 2. Output
```
================================================================================
Processing T1003.001
================================================================================
[OK] Config loaded: LSASS Memory Dumping
[PARSE] Reading log: windows-sysmon.log
        Parsed 7960 total events
[FILTER] Removed 816 Splunk events
         Remaining: 7144 events
[DETECT] Found 215 suspicious events
         Event 10 (ProcessAccess): 163
         Event 3 (Network): 30
         Event 1 (Process): 22

[GRAPH] Built provenance graph:
        Nodes: 23
        Edges: 46
        Node types: {'Event': 1, 'Process': 14, 'Network': 8}
        Reduction: 97.3%
[SAVE] Saved: T1003.001_graph_v2.json
```

## Configuration Files

### Global Whitelist (`configs/global_whitelist.json`)
```json
{
  "ignore_paths": [
    "C:\\Program Files\\Splunk",
    "C:\\Program Files\\SplunkUniversalForwarder",
    "C:\\Windows\\CCM",
    "C:\\ProgramData\\Microsoft\\Windows Defender"
  ],
  "ignore_processes": [
    "splunk-admon.exe",
    "splunk-powershell.exe",
    "splunkd.exe"
  ],
  "lolbins": [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "mshta.exe",
    "rundll32.exe"
  ]
}
```

### Technique Config Example (`configs/T1059.001.json`)
```json
{
  "technique_id": "T1059.001",
  "technique_name": "PowerShell Execution",
  "event_ids": [1, 10, 3],
  "focus_processes": ["powershell.exe", "pwsh.exe"],
  "suspicious_patterns": {
    "process_names": ["powershell.exe", "pwsh.exe"],
    "command_patterns": ["-enc", "iex", "downloadstring", "bypass"],
    "parent_processes": ["explorer.exe", "winword.exe", "excel.exe"]
  },
  "detection_logic": {
    "time_window_minutes": 5,
    "confidence": "CRITICAL"
  },
  "node_labels": {
    "Process": "PowerShell Execution",
    "Network": "PowerShell Network Connection"
  }
}
```

## Adding New Technique

### Step 1: Create Config File
Create `configs/T1053.json`:
```json
{
  "technique_id": "T1053",
  "technique_name": "Scheduled Task/Job",
  "event_ids": [1, 13],
  "focus_processes": ["schtasks.exe", "at.exe"],
  "suspicious_patterns": {
    "process_names": ["schtasks.exe", "at.exe"],
    "command_patterns": ["/create", "/sc", "/tn", "/tr"],
    "registry_keys": ["Schedule", "Tasks"]
  },
  "detection_logic": {
    "time_window_minutes": 5,
    "confidence": "HIGH"
  },
  "node_labels": {
    "Process": "Scheduled Task Tool",
    "Registry": "Task Registry Key"
  }
}
```

### Step 2: Add to Technique List
Edit `run_multig.py`:
```python
all_techniques = [
    'T1003.001',
    'T1003.002',
    # ... existing techniques
    'T1053',  # Add new technique
]
```

### Step 3: Run
```bash
python run_multig.py
```

## System Components

### 1. Config Loader
- Loads `global_whitelist.json` and technique-specific configs
- Validates JSON schema

### 2. Streaming XML Parser
- Regex-based: `r'<Event[^>]*>.*?</Event>'`
- Handles concatenated Sysmon XML
- Supports single-quote and double-quote attributes

### 3. Node ID Generator
- Priority 1: ProcessGuid (Sysmon)
- Priority 2: PID + Image
- Priority 3: PID only
- Fallback: TargetObject, TargetFilename

### 4. Hard Splunk Filter
- Filters ALL Splunk-related events
- Checks: Image, SourceImage, TargetImage, ParentImage
- Applied BEFORE detection (not after)

### 5. Detection Engine
- Config-driven pattern matching
- Supports: Process, Registry, File, Network events
- Confidence levels: MEDIUM, HIGH, CRITICAL

### 6. Graph Builder
- Uses ProcessGuid for edges
- Relationship types:
  - `CREATED`: Parent -> Child process
  - `TEMPORAL_RELATED`: Process -> Registry/File/Network
- OSSEM-compatible node types

### 7. Main Pipeline
- Orchestrates: Parse -> Filter -> Detect -> Build -> Save
- Progress logging with `[OK]`, `[ERROR]`, `[WARN]`

## Results

### Quality Comparison

| Technique | Old Nodes | New Nodes | Change | Status |
|-----------|-----------|-----------|--------|--------|
| T1003.001 | 30 | 23 | -23% | Improved focus |
| T1003.002 | 5 | 8 | +60% | More complete |
| T1059.001 | 114 | 50 | -56% | Removed Splunk |
| T1112 | 10 | 10 | 0% | Maintained |
| T1204.002 | 5 | 1 | -80% | Focused |
| T1218.005 | 50 | 50 | 0% | Maintained |
| T1218.011 | 32 | 32 | 0% | Maintained |
| T1482 | 30 | 6 | -80% | Better focus |
| T1547.001 | 5 | 8 | +60% | **Fixed** |
| T1548.002 | 3 | 11 | +267% | **Fixed** |

### Statistics
- **Total Nodes**: 199
- **Total Edges**: 524
- **Splunk Events Filtered**: 10,821
- **Average Reduction**: 93.3%
- **Quality Score**: 6/10 -> 9/10

## Export to Neo4j

### Generate Cypher
```python
import json

with open('output/T1059.001_graph_v2.json', 'r') as f:
    graph = json.load(f)

# Create nodes
for node_id, node_data in graph['nodes'].items():
    print(f"CREATE (n:{node_data['type']} {{id: '{node_id}', label: '{node_data['label']}'}})")

# Create edges
for edge in graph['edges']:
    print(f"MATCH (a {{id: '{edge['source']}'}}), (b {{id: '{edge['target']}'}}) " +
          f"CREATE (a)-[:{edge['relation']}]->(b)")
```

## Troubleshooting

### Check Parsing
```python
from run_multig import parse_sysmon_streaming, BASE_DIR

log_file = BASE_DIR / 'T1059.001' / 'windows-sysmon.log'
events = parse_sysmon_streaming(log_file)
print(f"Total events: {len(events)}")
```

### Check Filtering
```python
from run_multig import filter_splunk_noise, GLOBAL_CONFIG

filtered, removed = filter_splunk_noise(events, GLOBAL_CONFIG)
print(f"Removed: {removed}, Remaining: {len(filtered)}")
```

### Check Detection
```python
from run_multig import detect_suspicious_events, load_technique_config

config = load_technique_config('T1059.001')
suspicious = detect_suspicious_events(filtered, config, GLOBAL_CONFIG)
print(f"Suspicious: {len(suspicious)}")
```

## Use Cases

- **APT Campaign Analysis**: Detect multi-stage attacks
- **Threat Hunting**: Identify suspicious behavior patterns
- **SOC Automation**: Integrate with SIEM systems
- **Research**: Analyze attack techniques for papers
- **Neo4j Import**: Build graph database for visualization

## Technical Details

### Performance
- **Streaming Parser**: Memory-efficient for large logs
- **Regex-based**: Handles malformed XML gracefully
- **Event Reduction**: 93.3% average (raw -> graph)

### Compatibility
- **Sysmon**: Windows Sysmon logs (XML format)
- **MITRE ATT&CK**: 10 techniques supported
- **Neo4j**: OSSEM schema compatible
- **Python**: 3.7+

### Dependencies
- `pathlib`: File path handling
- `json`: Config loading
- `xml.etree.ElementTree`: XML parsing
- `re`: Regex-based streaming
- `collections`: Counter, defaultdict

## License

This is a research project. Use for academic and research purposes.

## Contact

For questions or issues, please open an issue in the repository.
