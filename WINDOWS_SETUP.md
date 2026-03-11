# Windows Desktop Launcher Setup Guide

This guide explains how to create a clickable desktop icon that runs the validator and displays results in Chrome.

## Quick Start

### Step 1: Create Desktop Shortcut

1. **Open File Explorer** and navigate to the validator directory (`C:\path\to\claude-nw-validator`)
2. **Right-click on `run_validator_hidden.vbs`** → **Send to** → **Desktop (create shortcut)**
   - This creates a shortcut on your desktop

### Step 2: Customize the Shortcut (Optional)

1. **Right-click the new desktop shortcut** → **Properties**
2. **Change the name** to "Network Validator" (or whatever you prefer)
3. **Change the icon** (see below for icon options)
4. **Click OK**

## How to Change the Icon

### Option A: Use a Built-in Windows Icon

1. **Right-click shortcut** → **Properties**
2. Click **Change Icon**
3. Browse to `C:\Windows\System32\shell32.dll` (contains hundreds of icons)
4. Choose a network-related icon (search for "network", "plug", or "globe")
5. Click **OK**

### Option B: Create a Custom Icon

Use an online ICO converter (google "PNG to ICO converter") to convert any image you want, then:

1. **Right-click shortcut** → **Properties**
2. Click **Change Icon**
3. Navigate to your custom `.ico` file
4. Click **OK**

## How It Works

When you click the shortcut:

1. **PowerShell script runs silently** in the background (no console window visible)
2. **Python validator executes** and:
   - Connects to your network devices
   - Runs all validation tests
   - Generates two HTML reports:
     - `network1_report.html` - Detailed test results (for debugging)
     - `network1_attendee_report.html` - Attendee-friendly summary (what opens in browser)
3. **Chrome automatically opens** with the attendee report
4. **User sees only the results** - all script execution is hidden

## File Structure

```
claude-nw-validator/
├── run_validator_hidden.vbs      ← Desktop shortcut points to this
├── run_validator.bat             ← Called by VBScript (runs PowerShell)
├── run_validator.ps1             ← Core script (runs Python, opens Chrome)
├── validator.py                  ← Main validation script
├── config/network1/              ← Configuration files
├── templates/                    ← HTML report templates
└── .venv/                        ← Python virtual environment
```

## Troubleshooting

### Shortcut doesn't work

- **Check Python path**: The script assumes `.venv\Scripts\python.exe` exists
- **Check Chrome installed**: If Chrome not at `C:\Program Files\Google\Chrome\Application\chrome.exe`, edit `run_validator.ps1`
- **Check network access**: Ensure device network accessibility from your machine

### Script is too slow

- This is normal - the validator runs multiple show commands on network devices
- First time may take 30+ seconds while connecting to devices
- Subsequent runs are faster once connections are cached

### PowerShell execution policy error

If you get a PowerShell error about execution policies:

1. Open **PowerShell as Administrator**
2. Run: `Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser`
3. Type `Y` and press Enter
4. Close PowerShell and try the shortcut again

## Customization

### Change the network config
Edit the path in `run_validator.ps1`:
```powershell
$configDir = Join-Path $scriptPath "config\network1"
```
Change `network1` to `network2`, etc.

### Change the report that opens
Edit `run_validator.ps1` to open the detailed report instead:
```powershell
# Change this line:
$reportPath = Join-Path $scriptPath "network1_attendee_report.html"

# To this:
$reportPath = Join-Path $scriptPath "network1_report.html"
```

### Change the browser
The script attempts to use Chrome but falls back to the default browser. To force a specific browser, edit `run_validator.ps1`:

**For Firefox:**
```powershell
$browserPath = "C:\Program Files\Mozilla Firefox\firefox.exe"
Start-Process $browserPath $reportPath
```

**For Edge:**
```powershell
$browserPath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
Start-Process $browserPath $reportPath
```

## For Attendees

Just tell attendees:
> "When you're ready to check your work, double-click the **Network Validator** icon on your desktop. A Chrome window will pop up with your validation results."

That's it! They don't need to know about:
- Python scripts
- SSH connections
- Test logic
- Virtual environments
- Command lines

They just see results! 🎯

## Example Desktop Setup

```
Desktop
├── 📋 Network Validator ← This is what attendees click
├── 📁 Lab Files
└── 📖 README
```

When clicked → Chrome opens with task validation results automatically

## Tips for Workshops

1. **Test it first** on your own machine before deploying to attendees
2. **Create the shortcut once**, then copy it to attendee machines
3. **Pin to Taskbar** (right-click shortcut → Pin to Taskbar) for even easier access
4. **Add to Start Menu** by creating a folder in `C:\Users\[User]\AppData\Roaming\Microsoft\Windows\Start Menu\Programs`
