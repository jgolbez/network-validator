' VBScript popup to show validation status
' Auto-closes after timeout, doesn't block the calling script

Set objShell = CreateObject("WScript.Shell")
objShell.Popup "Validation underway...", 25, "Network Validator", 0 + 64
