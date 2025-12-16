# 🛡️ MultiKG Real-time Detection System

## ✅ PRODUCTION VERSION - REAL SYSMON MONITORING

Hệ thống phát hiện APT attacks bằng cách:
- ✅ **Bắt log THẬT** từ Sysmon (không fake!)
- ✅ **Build provenance graph** từ events
- ✅ **Match với templates** từ knowledge base
- ✅ **Lưu detection history** vào logs/

---

## 🚀 QUICK START

### 1. Verify System
```powershell
# Check Sysmon
Get-Service Sysmon64

# Check events
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

### 2. Start Dashboard (Administrator!)
```powershell
cd d:\nckh\auditlog\demo_system
python -m streamlit run ui\live_detection.py --server.port=8503
```
**→ Opens at:** http://localhost:8503

### 3. Run Attack (New Terminal)
```powershell
cd attacks
.\T1059.001_powershell_execution.ps1
```

### 4. See Detection
Dashboard auto-refreshes every 5 seconds → Shows **THREAT DETECTED**!

---

## 📂 Structure
```
demo_system/
├── ui/
│   └── live_detection.py        ← Main dashboard (REAL logs!)
├── engine/
│   ├── log_collector.py         ← Sysmon collector
│   ├── graph_builder.py         ← Graph builder
│   └── matcher.py               ← Template matcher
├── knowledge_base/               ← 10 technique templates
├── attacks/                      ← Attack scripts
├── logs/
│   └── detected_attacks.json    ← Detection history (auto-created)
└── GUIDE.md                      ← Complete documentation
```

## 🚀 Setup Instructions (VM)

### 1. Prerequisites
- Windows 10/11 Pro (VM recommended)
- Python 3.10+
- Administrator privileges

### 2. Install Sysmon
```powershell
# Download Sysmon from Sysinternals
# Install with custom config
sysmon64.exe -accepteula -i config\sysmon_config.xml
```

### 3. Install Python Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Run Detection System
```powershell
# Terminal 1: Start Dashboard
cd ui
streamlit run dashboard.py

# Terminal 2: Run attack (in separate window)
cd attacks
powershell -ExecutionPolicy Bypass -File T1003.001_demo.ps1
```

## 🎨 Dashboard Features
- **Live Event Stream**: Real-time Sysmon events
- **Alert Panel**: Attack detection notifications
- **Graph Visualization**: Matched attack patterns

## 📊 Detected Techniques
1. T1003.001 - LSASS Memory Dump
2. T1003.002 - Security Account Manager
3. T1059.001 - PowerShell Execution
4. T1112 - Modify Registry
5. T1204.002 - Malicious File Execution
6. T1218.005 - Mshta Execution
7. T1218.011 - Rundll32 Execution
8. T1482 - Domain Trust Discovery
9. T1547.001 - Registry Run Keys
10. T1548.002 - Bypass UAC

## ⚠️ Warning
This system is for RESEARCH and EDUCATIONAL purposes only.
Run in isolated VM environment.
