' VBScript to silently run the lab startup batch file
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
strBatchFile = objFSO.BuildPath(strScriptDir, "start_lab.bat")
objShell.Run strBatchFile, 0, False
