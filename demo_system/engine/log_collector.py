"""
Sysmon Log Collector - Real-time Event Streaming
================================================
Monitors Microsoft-Windows-Sysmon/Operational log channel
and streams events for detection.
"""

import win32evtlog
import win32con
import win32evtlogutil
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, Optional, Generator
import time
from queue import Queue
import threading


class SysmonCollector:
    """
    Real-time Sysmon event collector using Windows Event Log API.
    """
    
    def __init__(self, event_queue: Queue, target_event_ids=None):
        """
        Initialize collector.
        
        Args:
            event_queue: Queue to push events to
            target_event_ids: List of Sysmon Event IDs to capture (None = all)
        """
        self.event_queue = event_queue
        self.channel = "Microsoft-Windows-Sysmon/Operational"
        self.running = False
        
        # Target Event IDs for attack detection
        self.target_event_ids = target_event_ids or [
            1,   # Process Create
            3,   # Network Connection
            7,   # Image Loaded
            8,   # CreateRemoteThread
            10,  # ProcessAccess
            11,  # FileCreate
            12,  # RegistryEvent (Object create/delete)
            13,  # RegistryEvent (Value Set)
            22,  # DNSEvent
        ]
    
    def parse_event_xml(self, xml_str: str) -> Optional[Dict]:
        """
        Parse Sysmon XML event into dictionary.
        """
        try:
            root = ET.fromstring(xml_str)
            
            # Extract System info
            system = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}System')
            event_id = int(system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text)
            
            # Accept ALL Sysmon events for now (debug mode)
            # if event_id not in self.target_event_ids:
            #     return None
            
            time_created = system.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated')
            timestamp = time_created.get('SystemTime')
            
            # Extract Event Data
            event_data = {}
            event_data_node = root.find('.//{http://schemas.microsoft.com/win/2004/08/events/event}EventData')
            
            if event_data_node is not None:
                for data in event_data_node:
                    name = data.get('Name')
                    value = data.text
                    if name and value:
                        event_data[name] = value
            
            return {
                'EventID': event_id,
                'Timestamp': timestamp,
                'Data': event_data
            }
            
        except Exception as e:
            print(f"[ERROR] Failed to parse event: {e}")
            return None
    
    def start_streaming(self):
        """
        Start streaming events (blocking call).
        """
        self.running = True
        print(f"[COLLECTOR] Starting Sysmon event stream...")
        print(f"[COLLECTOR] Target Event IDs: {self.target_event_ids}")
        
        # Open event log handle
        try:
            hand = win32evtlog.OpenEventLog(None, self.channel)
        except Exception as e:
            print(f"[ERROR] Cannot open Sysmon log: {e}")
            print("[ERROR] Make sure Sysmon is installed and running as Administrator")
            return
        
        # Get initial count to track new events
        initial_count = win32evtlog.GetNumberOfEventLogRecords(hand)
        print(f"[COLLECTOR] Initial event count: {initial_count}")
        print(f"[COLLECTOR] Will monitor for events > {initial_count}")
        print("[COLLECTOR] ✅ Streaming NEW events only...")
        
        # Main loop: Poll for new events
        event_count = 0
        last_checked_count = initial_count
        
        while self.running:
            try:
                # Check current total
                current_count = win32evtlog.GetNumberOfEventLogRecords(hand)
                
                if current_count > last_checked_count:
                    new_events_expected = current_count - last_checked_count
                    print(f"[COLLECTOR] ✨ NEW EVENTS DETECTED! Count: {last_checked_count} → {current_count} (+{new_events_expected})")
                    
                    # Read from end backwards to get newest events
                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                    events = win32evtlog.ReadEventLog(hand, flags, 0)
                    
                    if events:
                        print(f"[COLLECTOR] Read {len(events)} events from log")
                        # Process newest events (only the new ones)
                        for i, event in enumerate(events):
                            if i >= new_events_expected:
                                break  # Only process the new ones
                                
                            try:
                                # Get event XML
                                xml_str = win32evtlogutil.SafeFormatMessage(event, self.channel)
                                
                                # Parse
                                parsed = self.parse_event_xml(xml_str)
                                if parsed:
                                    self.event_queue.put(parsed)
                                    event_count += 1
                                    print(f"[COLLECTOR] ✅ Event {event_count}: ID={parsed['EventID']} → Queue (size={self.event_queue.qsize()})")
                                    
                                    if event_count % 10 == 0:
                                        print(f"[COLLECTOR] Milestone: {event_count} events collected")
                                else:
                                    print(f"[COLLECTOR] ⚠️ Event parsed as None")
                            
                            except Exception as e:
                                print(f"[COLLECTOR ERROR] Failed to process event: {e}")
                                continue
                    
                    last_checked_count = current_count
                else:
                    # No new events, wait
                    pass
                
                # Poll every 0.5 seconds
                time.sleep(0.5)
                
            except Exception as e:
                print(f"[COLLECTOR ERROR] Poll error: {e}")
                time.sleep(1)
        
        win32evtlog.CloseEventLog(hand)
        print(f"[COLLECTOR] Stopped. Total events: {event_count}")
    
    def stop(self):
        """Stop streaming."""
        self.running = False


def start_collector_thread(event_queue: Queue) -> threading.Thread:
    """
    Start collector in background thread.
    
    Returns:
        Thread object
    """
    collector = SysmonCollector(event_queue)
    thread = threading.Thread(target=collector.start_streaming, daemon=True)
    thread.start()
    return thread


# Example usage
if __name__ == "__main__":
    event_queue = Queue()
    
    print("Starting Sysmon collector...")
    print("Press Ctrl+C to stop\n")
    
    collector = SysmonCollector(event_queue)
    
    try:
        # Start in main thread (blocking)
        collector.start_streaming()
    except KeyboardInterrupt:
        print("\nStopping collector...")
        collector.stop()
