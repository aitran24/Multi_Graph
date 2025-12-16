"""
WebSocket Server for Real-time Sysmon Event Streaming
Reads Sysmon logs continuously and pushes to connected clients
"""

import asyncio
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
import websockets
import sys

# Add parent path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from engine.matcher import TemplateMatcher

# Configuration
WS_HOST = "localhost"
WS_PORT = 8765
POLL_INTERVAL = 1  # Check for new events every 1 second
MAX_EVENTS = 100

# Connected clients
connected_clients = set()

# Event tracking
last_event_time = None
event_buffer = []
detection_history = []

# Initialize matcher
matcher = None
knowledge_base_path = Path(__file__).parent.parent / "knowledge_base"

# Behavioral signatures for quick detection
BEHAVIORAL_SIGNATURES = {
    "T1059.001": {
        "name": "PowerShell Execution",
        "patterns": ["powershell", "pwsh", "-encodedcommand", "-enc", "invoke-expression", "iex", "downloadstring", "invoke-webrequest"],
        "event_types": [1]
    },
    "T1112": {
        "name": "Registry Modification", 
        "patterns": ["reg.exe", "reg add", "reg delete", "set-itemproperty", "new-itemproperty", "currentversion\\run"],
        "event_types": [1, 13]
    },
    "T1003.001": {
        "name": "LSASS Memory Dump",
        "patterns": ["lsass", "procdump", "mimikatz", "sekurlsa", "comsvcs.dll", "minidump"],
        "event_types": [1, 10]
    },
    "T1547.001": {
        "name": "Registry Run Keys",
        "patterns": ["currentversion\\run", "currentversion\\runonce", "startup"],
        "event_types": [1, 13]
    }
}

def init_matcher():
    """Initialize template matcher with knowledge base"""
    global matcher
    try:
        matcher = TemplateMatcher(str(knowledge_base_path))
        print(f"[INFO] Loaded {len(matcher.templates)} attack templates")
    except Exception as e:
        print(f"[WARN] Could not load templates: {e}")
        matcher = None

def get_sysmon_events(seconds_back=5):
    """Get recent Sysmon events using PowerShell"""
    ps_script = f'''
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 50 -ErrorAction SilentlyContinue | 
        Where-Object {{ $_.TimeCreated -gt (Get-Date).AddSeconds(-{seconds_back}) }} |
        Select-Object Id, TimeCreated, Message |
        ForEach-Object {{
            @{{
                EventID = $_.Id
                TimeCreated = $_.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                Message = $_.Message
            }}
        }}
    $events | ConvertTo-Json -Depth 3
    '''
    
    try:
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]
            return data
        return []
    except Exception as e:
        print(f"[ERROR] Failed to get events: {e}")
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
    
    return parsed

def check_behavioral_signature(event):
    """Check event against behavioral signatures"""
    detections = []
    message = event.get("raw_message", "").lower()
    event_id = event.get("event_id")
    
    # Skip dashboard's own commands
    skip_keywords = ["get-winevent", "sysmon/operational", "streamlit", "websocket"]
    if any(kw in message for kw in skip_keywords):
        return detections
    
    for tech_id, sig in BEHAVIORAL_SIGNATURES.items():
        if event_id in sig["event_types"]:
            matched_patterns = [p for p in sig["patterns"] if p in message]
            if matched_patterns:
                confidence = min(len(matched_patterns) / len(sig["patterns"]) + 0.3, 1.0)
                detections.append({
                    "technique_id": tech_id,
                    "technique_name": sig["name"],
                    "confidence": round(confidence * 100, 1),
                    "matched_patterns": matched_patterns,
                    "event": event
                })
    
    return detections

async def broadcast_event(event_data):
    """Broadcast event to all connected clients"""
    if connected_clients:
        message = json.dumps(event_data)
        await asyncio.gather(
            *[client.send(message) for client in connected_clients],
            return_exceptions=True
        )

async def monitor_sysmon():
    """Continuously monitor Sysmon events and broadcast"""
    global last_event_time, detection_history
    
    print(f"[INFO] Starting Sysmon monitor...")
    
    while True:
        try:
            events = get_sysmon_events(POLL_INTERVAL + 1)
            
            for event in events:
                parsed = parse_event(event)
                
                # Check for attacks
                detections = check_behavioral_signature(parsed)
                
                if detections:
                    for det in detections:
                        detection_record = {
                            "type": "detection",
                            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "technique_id": det["technique_id"],
                            "technique_name": det["technique_name"],
                            "confidence": det["confidence"],
                            "patterns": det["matched_patterns"],
                            "source": parsed.get("image", parsed.get("commandline", "N/A"))[:100],
                            "event_id": parsed.get("event_id"),
                            "status": "ALERT"
                        }
                        detection_history.append(detection_record)
                        detection_history = detection_history[-50:]  # Keep last 50
                        
                        await broadcast_event(detection_record)
                        print(f"[ALERT] {det['technique_id']} - {det['technique_name']} ({det['confidence']}%)")
                
                # Also broadcast raw event for log view
                event_record = {
                    "type": "event",
                    "timestamp": parsed.get("timestamp"),
                    "event_id": parsed.get("event_id"),
                    "image": parsed.get("image", "N/A"),
                    "commandline": parsed.get("commandline", "")[:200] if parsed.get("commandline") else "",
                    "user": parsed.get("user", "N/A"),
                    "target": parsed.get("targetfilename", parsed.get("targetobject", "N/A"))
                }
                await broadcast_event(event_record)
            
        except Exception as e:
            print(f"[ERROR] Monitor error: {e}")
        
        await asyncio.sleep(POLL_INTERVAL)

async def handle_client(websocket):
    """Handle WebSocket client connection"""
    connected_clients.add(websocket)
    client_id = id(websocket)
    print(f"[INFO] Client connected: {client_id} (Total: {len(connected_clients)})")
    
    try:
        # Send initial status
        await websocket.send(json.dumps({
            "type": "status",
            "message": "Connected to Sysmon Monitor",
            "clients": len(connected_clients)
        }))
        
        # Send recent detection history
        if detection_history:
            await websocket.send(json.dumps({
                "type": "history",
                "data": detection_history[-20:]
            }))
        
        # Keep connection alive
        async for message in websocket:
            # Handle client messages if needed
            data = json.loads(message)
            if data.get("command") == "get_history":
                await websocket.send(json.dumps({
                    "type": "history",
                    "data": detection_history[-20:]
                }))
    
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        connected_clients.discard(websocket)
        print(f"[INFO] Client disconnected: {client_id} (Total: {len(connected_clients)})")

async def main():
    """Main server entry point"""
    init_matcher()
    
    # Start WebSocket server
    server = await websockets.serve(handle_client, WS_HOST, WS_PORT)
    print(f"[INFO] WebSocket server started on ws://{WS_HOST}:{WS_PORT}")
    
    # Start Sysmon monitor
    monitor_task = asyncio.create_task(monitor_sysmon())
    
    print("[INFO] Server ready. Waiting for connections...")
    
    await asyncio.gather(server.wait_closed(), monitor_task)

if __name__ == "__main__":
    print("=" * 60)
    print("  MultiKG Real-time Sysmon Monitor - WebSocket Server")
    print("=" * 60)
    print()
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[INFO] Server stopped.")
