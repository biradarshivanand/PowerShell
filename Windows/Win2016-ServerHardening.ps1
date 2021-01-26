#Group ID: V-73495
#Comments: ConfigOS needs this to work remotely, as well as several other scanning tools
New-Item -ItemType directory -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ -Force
Set-ItemProperty -Name localaccounttokenfilterpolicy -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\ -Value 0x00000000
Get-ItemProperty -Name localaccounttokenfilterpolicy -Path HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\
#Group ID: V-73497
#Comments: This policy setting requires the installation of the SecGuide custom templates included with the STIG package. "SecGuide.admx" and " SecGuide.adml" must be copied to the \Windows\PolicyDefinitions and \Windows\PolicyDefinitions\en-US directories respectively.
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\ -Force
Set-ItemProperty -Name UseLogonCredentialType -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\ -Value 0x00000000
Get-ItemProperty -Name UseLogonCredentialType -Path HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest\
#Group ID: V-73521
#Comments: A value of 1,3,or 8 is also acceptable. Changing boot behavior is dangerous.
#Our Comment:Since there was no Expected Value give we set it to 1 which means (PNP_INITIALIZE_UNKNOWN_DRIVERS 0x1)
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ -Force
Set-ItemProperty -Name DriverLoadPolicy -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ -Value 0x00000001
Get-ItemProperty -Name DriverLoadPolicy -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
#Group ID: V-73537
#Comments:
New-Item -ItemType directory -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ -Force
Set-ItemProperty -Name DCSettingIndex -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ -Value 0x00000001
Get-ItemProperty -Name DCSettingIndex -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
#Group ID: V-73539
#Comments:
New-Item -ItemType directory -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ -Force
Set-ItemProperty -Name ACSettingIndex -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ -Value 0x00000001
Get-ItemProperty -Name ACSettingIndex -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
#Group ID: V-73629
#Comments:
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\ -Force
Set-ItemProperty -Name LDAPServerIntegrity -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\ -Value 0x00000002
Get-ItemProperty -Name LDAPServerIntegrity -Path HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\
#Group ID: V-73631
#Comments:
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Force
Set-ItemProperty -Name RefusePasswordChange -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Value 0x00000000
Get-ItemProperty -Name RefusePasswordChange -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ 
#Group ID: V-73651
#Comments:
#Our Comment:Since the expected value is a maximum of 4, we have set the value to 4
New-Item -ItemType directory -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Force
Set-ItemProperty -Name CachedLogonsCount -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\" -Value 0x00000004
Get-ItemProperty -Name CachedLogonsCount -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\"
#Group ID: V-73699
#Comments: 
New-Item -ItemType directory -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\ -Force
Set-ItemProperty -Name ForceKeyProtection -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\ -Value 0x00000002
Get-ItemProperty -Name ForceKeyProtection -Path HKLM:\SOFTWARE\Policies\Microsoft\Cryptography\

#Group ID: V-73511
#Comments: 
New-Item -ItemType directory -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ -Force
Set-ItemProperty -Name ProcessCreationIncludeCmdLine_Enabled -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ -Value 0x00000001
Get-ItemProperty -Name ProcessCreationIncludeCmdLine_Enabled -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit\
#Group ID: V-73521
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ -Force
Set-ItemProperty -Name DriverLoadPolicy -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\ -Value 0x00000003
Get-ItemProperty -Name DriverLoadPolicy -Path HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch\
#Group ID: V-73537
#Comments: 
New-Item -ItemType directory -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ -Force
Set-ItemProperty -Name DCSettingIndex -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\ -Value 0x00000001
Get-ItemProperty -Name DCSettingIndex -Path HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51\
#Group ID: V-73633
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Force
Set-ItemProperty -Name RequireSignOrSeal -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Value 0x00000001
Get-ItemProperty -Name RequireSignOrSeal -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#Group ID: V-73635
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Force
Set-ItemProperty -Name SealSecureChannel -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Value 0x00000001
Get-ItemProperty -Name SealSecureChannel -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#Group ID: V-73637
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Force
Set-ItemProperty -Name SignSecureChannel -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Value 0x00000001
Get-ItemProperty -Name SignSecureChannel -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#Group ID: V-73639
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Force
Set-ItemProperty -Name DisablePasswordChange -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Value 0x00000000
Get-ItemProperty -Name DisablePasswordChange -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#Group ID: V-73641
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Force
Set-ItemProperty -Name MaximumPasswordAge -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Value 0x0000001e
Get-ItemProperty -Name MaximumPasswordAge -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#Group ID: V-73643
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Force
Set-ItemProperty -Name RequireStrongKey -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\ -Value 0x00000001
Get-ItemProperty -Name RequireStrongKey -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\
#Group ID: V-73685
#Comments: 
New-Item -ItemType directory -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ -Force
Set-ItemProperty -Name SupportedEncryptionTypes -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\ -Value 0x7ffffff8
Get-ItemProperty -Name SupportedEncryptionTypes -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\
#Group ID: V-73499
#Comments: 
New-Item -ItemType directory -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ -Force
Set-ItemProperty -Name DisableIPSourceRouting -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\ -Value 0x00000002
Get-ItemProperty -Name DisableIPSourceRouting -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\

#Group ID: V-73777
#Comments: 
$CarbonDllPath = "C:\Users\Administrator\Downloads\Carbon-1.6.0\Carbon\bin\Carbon.dll"
[Reflection.Assembly]::LoadFile($CarbonDllPath)
[Carbon.Lsa]::GrantPrivileges( "Guests" , "SeDenyNetworkLogonRight")
[Carbon.Lsa]::GrantPrivileges( "Guests" , "SeDenyBatchLogonRight")
[Carbon.Lsa]::GrantPrivileges( "Guests" , "SeInteractiveLogonRight")
[Carbon.Lsa]::GrantPrivileges( "Administrators" , "SeEnableDelegationPrivilege")
[Carbon.Lsa]::GrantPrivileges( "Administrators" , "SeSecurityPrivilege")
[Carbon.Lsa]::GrantPrivileges( "Guests group" , "SeDenyRemoteInteractiveLogonRight")
[Carbon.Lsa]::GrantPrivileges( "Guests Group" , "SeDenyInteractiveLogonRight")
[Carbon.Lsa]::GrantPrivileges( "Administrators" , "SeRemoteInteractiveLogonRight")
#73319
net accounts /minpwage:1
#73321
net accounts /MINPWLEN:14


