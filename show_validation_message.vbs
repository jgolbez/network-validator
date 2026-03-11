' VBScript popup to show validation status
' No buttons, no user interaction needed
' Will be closed by the calling PowerShell script when validation completes

Set objShell = CreateObject("WScript.Shell")
objShell.Popup "Validation underway...", 3600, "Network Validator", 0 + 64
