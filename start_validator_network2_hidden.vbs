' VBScript to silently run the validator batch file for network2
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
strBatchFile = objFSO.BuildPath(strScriptDir, "start_validator_network2.bat")
objShell.Run strBatchFile, 0, False
