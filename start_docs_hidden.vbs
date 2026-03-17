' VBScript to silently run the docs startup batch file
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)
strBatchFile = objFSO.BuildPath(strScriptDir, "start_docs.bat")
objShell.Run strBatchFile, 0, False
