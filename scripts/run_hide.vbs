Set ws = CreateObject("WScript.Shell")
scriptPath = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
ws.Run "powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & scriptPath & "\run.ps1""", 0, False
