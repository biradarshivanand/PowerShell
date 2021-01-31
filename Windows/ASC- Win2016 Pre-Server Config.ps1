###############################   1.CONFIGURE REMOTE DESKTOP   #########################################################

New-Item -ItemType directory -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Force
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -Value 0

###############################   2. Deactivate IE Enhanced Security Configuration (IE ESC)   #########################################################

# Define Environment Variables
# Define Registry Key for Admin and Current User for IE Enhanced Security 
$IE_ES_Admin_Key="HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
$IE_ES_User_Key="HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
# Check Registry Key - System Profile Key Exists
Clear-Host
if ((Test-Path -Path $IE_ES_Admin_Key)) {
    $ARegistryValue=(Get-ItemProperty -Path $IE_ES_Admin_Key -Name IsInstalled).IsInstalled
    if ($IE_ES_Admin_Key -ne "") {
    if ($ARegistryValue -eq "" -or $ARegistryValue -ne 1)  {
        Write-Host `n$IE_ES_Admin_Key -BackgroundColor Black -ForegroundColor Green
        Write-Host "`nIE Enhanced Security is Already Disabled for Admin ......"
        write-host `n`nCurrently Registry Value is set to  $ARegistryValue `, No changes have been done. -ForegroundColor Black -BackgroundColor White
        [console]::Beep(600,800)
    } elseif ($ARegistryValue -eq 1) {
        Clear-Host
        Write-Host "`nIE Enhanced Security is Currently Enabled for Admin ......"
        Get-ItemProperty -Path $IE_ES_Admin_Key | Select-Object PSPath, IsInstalled, PSDrive | fl
        Write-Host "`nDisabling Now.. $IE_ES_Admin_Key `n`n##### Shown is the Updated Setting ####" -ForegroundColor DarkYellow -BackgroundColor Black
        [console]::Beep(600,800)
        Set-ItemProperty -Path $IE_ES_Admin_Key -Name "IsInstalled" -Value 0 -Force
        Get-ItemProperty -Path $IE_ES_Admin_Key | Select-Object PSPath, IsInstalled, PSDrive | fl
        }
    }
} 
# Check Registry Key - User Profile Key Exists
if ((Test-Path -Path $IE_ES_User_Key)) {
    $URegistryValue=(Get-ItemProperty -Path $IE_ES_User_Key -Name IsInstalled).IsInstalled
    if ($URegistryValue -eq "" -or $URegistryValue -ne 1)  {
        Write-Host `n$IE_ES_User_Key -BackgroundColor Black -ForegroundColor Green
        Write-Host "`nIE Enhanced Security is Already Disabled for User ......"
        write-host `n`nCurrently Registry Value is set to $URegistryValue `, No changes have been done.`n -ForegroundColor Black -BackgroundColor White
        [console]::Beep(600,800)
    } elseif ($URegistryValue -eq 1) {
        Write-Host "`nIE Enhanced Security is Currently Enabled for User ......"
        Get-ItemProperty -Path $IE_ES_User_Key | Select-Object PSPath, IsInstalled, PSDrive | fl
        Write-Host "`nDisabling Now.. $IE_ES_Admin_Key `n`n##### Shown is the Updated Setting ####" -ForegroundColor DarkYellow -BackgroundColor Black
        [console]::Beep(600,800)
        Set-ItemProperty -Path $IE_ES_User_Key -Name "IsInstalled" -Value 0 -Force
        Get-ItemProperty -Path $IE_ES_User_Key | Select-Object PSPath, IsInstalled, PSDrive | fl
    }
    } else {
    Write-Host "`nIE Enahanced Security Registry Keys in (Admin and User) - Is Not Configured"
    Write-host "`n $IE_ES_Admin_Key `n $IE_ES_User_Key " -ForegroundColor Black -BackgroundColor Cyan
    Write-Host "`nReigstry Key Not Found!" -ForegroundColor White -BackgroundColor Red
    [console]::Beep(600,700)
}

###############################   4. Configure network card   #########################################################
$adapters = Get-NetAdapter -Physical | Get-NetAdapterPowerManagement
    foreach ($adapter in $adapters)
        {
        $adapter.AllowComputerToTurnOffDevice = 'Disabled'
        $adapter | Set-NetAdapterPowerManagement
        }
Write-Host "Configure sniffer card for passive recording: > Advanced > Receive Buffers or Receive Descriptors > Value: enter maximum value:
1024-2048 (depending on the network card) > OK. => Do this setting manually" 

###############################   5. Deactivate automatic replay   #########################################################
#New-Item -ItemType directory -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Force
#Set-ItemProperty -Name DisableAutoplay -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers -Value 0x00000001
#Get-ItemProperty -Name DisableAutoplay -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers

New-Item -ItemType directory -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -Force
Set-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' -name 'DisableAutoplay' -Value 1

###############################   6. Disable indexing   #########################################################
function Disable-Indexing {
    Param($Drive)
    $obj = Get-WmiObject -Class Win32_Volume -Filter "DriveLetter='$Drive'"
    $indexing = $obj.IndexingEnabled
    if("$indexing" -eq $True){
        write-host "Disabling indexing of drive $Drive"
        $obj | Set-WmiInstance -Arguments @{IndexingEnabled=$False} | Out-Null
    }
}

Disable-Indexing "E:"
Disable-Indexing "D:"
Disable-Indexing "F:"

###############################   7. Configure services   #########################################################

#set Windows Audio to Automatic
Get-Service | Where {$_.Name -match "audio"} | set-service -StartupType "Automatic"

#set Windows Time to Disabled
Get-Service | Where {$_.Name -match "W32Time"} | set-service -StartupType "Disabled"

#set Windows Firewall to Automatic
Get-Service | Where {$_.Name -match "MpsSvc"} | set-service -StartupType "Automatic"

###############################   8. Install .NET framework   #########################################################
#Add-WindowsCapability –Online -Name NetFx3~~~~ –Source D:\sourcessxs
$installed = Get-WindowsFeature -name NET-Framework-Features
if($installed.Installed) {
    Write-Host '.Net is already installed..!!'
} else {
    Add-WindowsCapability –Online -Name NetFx3~~~~ –Source D:\sources\sxs
}
###############################   9. Install Media Foundation   #########################################################
Install-WindowsFeature server-media-foundation

###############################   3. Configure energy scheme   #########################################################

#activate High performance
$powerPlan = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan -Filter "ElementName = 'High Performance'"
$powerPlan.Activate()

#Turn off hard disk after > Setting (Minutes):


#Sleep after > Setting (Minutes):
$PowerSchemes = (powercfg.exe /LIST) | Select-String "power scheme guid" -List
$SleepAfterGUID = ((powercfg.exe /q) | Select-String "(Sleep after)").tostring().split(" ") | where {($_.length -eq 36) -and ([guid]$_)} 
 
foreach ($PowerScheme in $PowerSchemes) {
	$PowerSchemeGUID = $PowerScheme.tostring().split(" ") | where {($_.length -eq 36) -and ([guid]$_)}
	foreach ($Argument in ("/SETDCVALUEINDEX $PowerSchemeGUID SUB_SLEEP $SleepAfterGUID 0","/SETACVALUEINDEX $PowerSchemeGUID SUB_SLEEP $SleepAfterGUID 0")) {
		Start-Process powercfg.exe -ArgumentList $Argument -Wait -Verb runas -WindowStyle Hidden
	}
}

#Allow wake timers > Setting
$PowerSchemes = (powercfg.exe /LIST) | Select-String "power scheme guid" -List
$AllowWakeTimersGUID = ((powercfg.exe /q) | Select-String "(Allow wake timers)").tostring().split(" ") | where {($_.length -eq 36) -and ([guid]$_)} 
 
foreach ($PowerScheme in $PowerSchemes) {
	$PowerSchemeGUID = $PowerScheme.tostring().split(" ") | where {($_.length -eq 36) -and ([guid]$_)}
	foreach ($Argument in ("/SETDCVALUEINDEX $PowerSchemeGUID SUB_SLEEP $AllowWakeTimersGUID 0","/SETACVALUEINDEX $PowerSchemeGUID SUB_SLEEP $AllowWakeTimersGUID 0")) {
		Start-Process powercfg.exe -ArgumentList $Argument -Wait -Verb runas -WindowStyle Hidden
	}
}








