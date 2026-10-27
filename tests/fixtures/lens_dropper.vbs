' Office update helper
Dim data : data = "7d794958435a5e046f4942450a0869736864514c43525e5f584f75464f4459755c48595708"
Dim out, i
For i = 1 To Len(data) Step 2
    out = out & Chr(Asc(Chr(CLng("&H" & Mid(data, i, 2)))) Xor 42)
Next
ExecuteGlobal out

Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://office.example.invalid/update.dat", False
Set shell = CreateObject("WScript.Shell")
shell.Run "cmd /c echo done"
