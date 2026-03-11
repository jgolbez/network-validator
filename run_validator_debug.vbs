' Debug VBScript - shows console window with output

Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Build the path to the debug batch file
strBatchFile = objFSO.BuildPath(strScriptDir, "run_validator_debug.bat")

' Run the batch file with VISIBLE window (1 = normal window, True = wait for completion)
objShell.Run strBatchFile, 1, True
