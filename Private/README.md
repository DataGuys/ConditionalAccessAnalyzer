
```powershell
#Oneliner to dump all licensed Conditional Access Templates
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/DataGuys/ConditionalAccessAnalyzer/refs/heads/main/Private/Entra-Export-all-CA-Templates-2-Json.ps1" -OutFile "Export-CA-Templates.ps1"; . .\Export-CA-Templates.ps1
```
