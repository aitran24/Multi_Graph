"""
Sysmon Event Collector - Backend Service
Reads Sysmon logs continuously and writes to shared JSON file
"""

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
import sys
import re

# Paths
BASE_DIR = Path(__file__).parent.parent
DATA_FILE = BASE_DIR / "logs" / "realtime_data.json"
HISTORY_FILE = BASE_DIR / "logs" / "detection_history.json"

# Configuration
POLL_INTERVAL = 1  # Check for new events every 1 second
MAX_EVENTS = 100
MAX_DETECTIONS = 50

# Behavioral signatures for quick detection - ALL 10 TECHNIQUES
BEHAVIORAL_SIGNATURES = {
    "T1003.001": {
        "name": "LSASS Memory Dump",
        "tactic": "Credential Access",
        "patterns": ["lsass", "procdump", "mimikatz", "sekurlsa", "comsvcs.dll", "minidump", "createdump"],
        "event_types": [1, 10]
    },
    "T1003.002": {
        "name": "SAM Database Dump",
        "tactic": "Credential Access", 
        "patterns": ["\\sam", "hklm\\sam", "vssadmin", "shadow", "ntds.dit", "system32\\config\\sam"],
        "event_types": [1, 13]
    },
    "T1059.001": {
        "name": "PowerShell Execution",
        "tactic": "Execution",
        "patterns": ["powershell", "pwsh", "-encodedcommand", "-enc", "invoke-expression", "iex", "downloadstring", "invoke-webrequest", "bypass", "-nop", "-w hidden"],
        "event_types": [1]
    },
    "T1112": {
        "name": "Registry Modification", 
        "tactic": "Defense Evasion",
        "patterns": ["reg.exe", "reg add", "reg delete", "set-itemproperty", "new-itemproperty", "hidefileext", "explorer\\advanced"],
        "event_types": [1, 13]
    },
    "T1204.002": {
        "name": "Malicious File Execution",
        "tactic": "Execution",
        "patterns": ["wscript", "cscript", ".vbs", ".hta", ".js", "mshta", "winword", "excel", "cmd.exe /c"],
        "event_types": [1]
    },
    "T1218.005": {
        "name": "Mshta Execution",
        "tactic": "Defense Evasion",
        "patterns": ["mshta", ".hta", "hta:application"],
        "event_types": [1]
    },
    "T1218.011": {
        "name": "Rundll32 Execution",
        "tactic": "Defense Evasion",
        "patterns": ["rundll32", "javascript:", "vbscript:", "shell32.dll", "user32.dll"],
        "event_types": [1, 5]
    },
    "T1482": {
        "name": "Domain Trust Discovery",
        "tactic": "Discovery",
        "patterns": ["nltest", "domain_trusts", "dsquery", "get-addomain", "get-adtrust", "net view /domain"],
        "event_types": [1]
    },
    "T1547.001": {
        "name": "Registry Run Keys Persistence",
        "tactic": "Persistence",
        "patterns": ["currentversion\\run", "currentversion\\runonce", "startup", "winlogon"],
        "event_types": [1, 13]
    },
    "T1548.002": {
        "name": "UAC Bypass",
        "tactic": "Privilege Escalation",
        "patterns": ["fodhelper", "eventvwr", "ms-settings", "mscfile", "delegateexecute", "computerdefaults"],
        "event_types": [1, 13]
    }
}

# Skip patterns (to avoid detecting ourselves)
SKIP_PATTERNS = [
    "get-winevent",
    "sysmon/operational", 
    "streamlit",
    "sysmon_collector",
    "python.exe\" -m streamlit",
    "convertto-json"
]

# Runtime data
events_buffer = []
detections_buffer = []
stats = {
    "total_events": 0,
    "start_time": None
}

def get_sysmon_events(seconds_back=2):
    """Get recent Sysmon events using PowerShell"""
    ps_script = f'''
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 30 -ErrorAction SilentlyContinue | 
        Where-Object {{ $_.TimeCreated -gt (Get-Date).AddSeconds(-{seconds_back}) }} |
        Select-Object Id, TimeCreated, Message |
        ForEach-Object {{
            @{{
                EventID = $_.Id
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Message = $_.Message
            }}
        }}
    if ($events) {{ $events | ConvertTo-Json -Depth 3 -Compress }} else {{ "[]" }}
    '''
    
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout.strip()
            if output == "[]" or not output:
                return []
            data = json.loads(output)
            if isinstance(data, dict):
                data = [data]
            return data
        return []
    except Exception as e:
        return []

def parse_event(event):
    """Parse Sysmon event message into structured data"""
    parsed = {
        "event_id": event.get("EventID"),
        "timestamp": event.get("TimeCreated"),
        "raw_message": event.get("Message", "")
    }
    
    message = event.get("Message", "")
    lines = message.split("\n")
    
    for line in lines:
        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip().lower().replace(" ", "_")
            value = value.strip()
            if key and value:
                parsed[key] = value
    
    # Handle different event types for better field extraction
    event_id = event.get("EventID")
    
    # Event ID 10 (ProcessAccess) uses SourceImage instead of Image
    if event_id == 10:
        if "sourceimage" in parsed:
            parsed["image"] = parsed["sourceimage"]
        if "sourceuser" in parsed:
            parsed["user"] = parsed["sourceuser"]

    # Normalise common field names for backwards compatibility
    # Some code expects keys without underscores (e.g., commandline, parentimage)
    # and some parsers produce keys with underscores (e.g., command_line)
    # Mirror both styles on the parsed dict.
    keys_snapshot = list(parsed.keys())
    for k in keys_snapshot:
        v = parsed.get(k)
        if isinstance(k, str):
            no_under = k.replace("_", "")
            if no_under not in parsed:
                parsed[no_under] = v

    # Explicit common mappings
    if "command_line" in parsed and "commandline" not in parsed:
        parsed["commandline"] = parsed["command_line"]
    if "target_filename" in parsed and "targetfilename" not in parsed:
        parsed["targetfilename"] = parsed["target_filename"]
    if "parent_image" in parsed and "parentimage" not in parsed:
        parsed["parentimage"] = parsed["parent_image"]
    if "target_image" in parsed and "targetimage" not in parsed:
        parsed["targetimage"] = parsed["target_image"]
    
    # If commandline fields are missing, try to extract them from the raw message
    raw_msg = parsed.get("raw_message", "") or ""
    if (not parsed.get("commandline")) and raw_msg:
        m = re.search(r"CommandLine:\s*(.*)", raw_msg, re.IGNORECASE)
        if m:
            parsed["commandline"] = m.group(1).strip()
            parsed["command_line"] = parsed["commandline"]

    # Parent command line (if present)
    if (not parsed.get("parentcommandline")) and raw_msg:
        m2 = re.search(r"ParentCommandLine:\s*(.*)", raw_msg, re.IGNORECASE)
        if m2:
            parsed["parentcommandline"] = m2.group(1).strip()
            parsed["parent_commandline"] = parsed["parentcommandline"]
    return parsed

def should_skip(message):
    """Check if event should be skipped"""
    message_lower = message.lower()
    return any(skip in message_lower for skip in SKIP_PATTERNS)

def check_behavioral_signature(event):
    """Check event against behavioral signatures"""
    detections = []
    # Build a combined search text including raw message, commandline, image and parent image
    raw = event.get("raw_message", "") or ""
    cmd = event.get("commandline", "") or ""
    img = event.get("image", "") or ""
    parent = event.get("parentimage", "") or ""
    search_text = " ".join([raw, cmd, img, parent]).lower()
    event_id = event.get("event_id")
    
    if should_skip(search_text):
        return detections
    
    for tech_id, sig in BEHAVIORAL_SIGNATURES.items():
        if event_id in sig["event_types"]:
            matched_patterns = [p for p in sig["patterns"] if p in search_text]
            if matched_patterns:
                confidence = min(len(matched_patterns) / len(sig["patterns"]) + 0.3, 1.0)
                
                # Extract command line or other relevant info from message
                cmd_line = event.get("commandline", "")
                image = event.get("image", "N/A")
                target = event.get("targetfilename", event.get("targetobject", ""))
                
                detections.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "technique_id": tech_id,
                    "technique_name": sig["name"],
                    "tactic": sig.get("tactic", "Unknown"),
                    "confidence": round(confidence * 100, 1),
                    "patterns": matched_patterns,
                    "source": image,
                    "command_line": cmd_line,
                    "target": target,
                    "event_id": event_id,
                    "matched_events": [{
                        "event_id": event.get("event_id"),
                        "timestamp": event.get("timestamp"),
                        "image": image,
                        "commandline": cmd_line,
                        "target_filename": target,
                        "details": event.get("details", ""),
                        "user": event.get("user", ""),
                        "parent_image": event.get("parentimage", ""),
                        "target_image": event.get("targetimage", "")
                    }]
                })
    
    return detections

def save_data():
    """Save current data to JSON file"""
    data = {
        "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "stats": {
            "total_events": stats["total_events"],
            "total_detections": len(detections_buffer),
            "uptime_seconds": int(time.time() - stats["start_time"]) if stats["start_time"] else 0
        },
        "events": events_buffer[-MAX_EVENTS:],
        "detections": detections_buffer[-MAX_DETECTIONS:]
    }
    
    try:
        DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(DATA_FILE, 'w') as f:
            json.dump(data, f)
    except Exception as e:
        print(f"[ERROR] Failed to save data: {e}")

def save_history():
    """Save detection history to persistent file"""
    try:
        with open(HISTORY_FILE, 'w') as f:
            json.dump(detections_buffer[-MAX_DETECTIONS:], f, indent=2)
    except Exception:
        pass

def load_history():
    """Load detection history from file"""
    global detections_buffer
    try:
        if HISTORY_FILE.exists():
            with open(HISTORY_FILE, 'r') as f:
                detections_buffer = json.load(f)
    except Exception:
        detections_buffer = []

def main():
    """Main collector loop"""
    global events_buffer, detections_buffer, stats
    
    print("=" * 60)
    print("  MultiKG Sysmon Collector - Backend Service")
    print("=" * 60)
    print()
    print(f"[INFO] Data file: {DATA_FILE}")
    print(f"[INFO] Poll interval: {POLL_INTERVAL}s")
    print()
    
    # Load previous history
    load_history()
    
    stats["start_time"] = time.time()
    last_timestamps = set()
    
    print("[INFO] Starting collection... Press Ctrl+C to stop")
    print()
    
    try:
        while True:
            events = get_sysmon_events(POLL_INTERVAL + 1)
            new_events = 0
            
            for event in events:
                # Deduplicate by timestamp
                ts = event.get("TimeCreated")
                if ts in last_timestamps:
                    continue
                last_timestamps.add(ts)
                
                # Keep only recent timestamps
                if len(last_timestamps) > 100:
                    last_timestamps = set(list(last_timestamps)[-50:])
                
                parsed = parse_event(event)
                
                # Skip our own events
                if should_skip(parsed.get("raw_message", "")):
                    continue
                
                # Add to events buffer
                event_record = {
                    "timestamp": parsed.get("timestamp"),
                    "event_id": parsed.get("event_id"),
                    "image": parsed.get("image", "N/A"),
                    "commandline": (parsed.get("commandline", "") or "")[:200],
                    "user": parsed.get("user", "N/A"),
                    "target": parsed.get("targetfilename", parsed.get("targetobject", "")),
                    "raw_message": (parsed.get("raw_message", "") or "")[:1000]
                }
                events_buffer.append(event_record)
                events_buffer = events_buffer[-MAX_EVENTS:]
                stats["total_events"] += 1
                new_events += 1
                
                # Check for attacks
                detections = check_behavioral_signature(parsed)
                
                for det in detections:
                    detection_record = {
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "technique_id": det["technique_id"],
                        "technique_name": det["technique_name"],
                        "confidence": det["confidence"],
                        "patterns": det["patterns"],
                        "source": parsed.get("image", parsed.get("commandline", "N/A"))[:100],
                        "event_id": parsed.get("event_id"),
                        "command_line": det.get("command_line", ""),
                        "matched_events": det.get("matched_events", [])
                    }
                    detections_buffer.append(detection_record)
                    detections_buffer = detections_buffer[-MAX_DETECTIONS:]
                    
                    print(f"[ALERT] {det['technique_id']} - {det['technique_name']} ({det['confidence']}%)")
                    save_history()
            
            if new_events > 0:
                print(f"[INFO] Processed {new_events} new events (Total: {stats['total_events']})")
            
            # Save data for frontend
            save_data()
            
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print("\n[INFO] Collector stopped.")
        save_data()
        save_history()

if __name__ == "__main__":
    main()
