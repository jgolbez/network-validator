' VBScript to run the batch file with hidden console window
' This is what the desktop shortcut will actually call

' Create a WScript Shell object
Set objShell = CreateObject("WScript.Shell")

' Get the directory where this script is located
strScriptPath = objShell.CurrentDirectory
Set objFSO = CreateObject("Scripting.FileSystemObject")
strScriptDir = objFSO.GetParentFolderName(WScript.ScriptFullName)

' Build the path to the batch file
strBatchFile = objFSO.BuildPath(strScriptDir, "run_validator.bat")

' Run the batch file with hidden window (0 = hidden, False = don't wait)
objShell.Run strBatchFile, 0, False
