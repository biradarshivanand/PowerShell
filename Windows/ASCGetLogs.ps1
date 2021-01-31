$servers = @("10.0.0.185","10.0.0.186")
$StartTime = "6/5/2020 00:00:00"
$EndTime = "6/25/2020 00:00:00"
$dst = New-Item -ItemType Directory -Path "$($env:USERPROFILE)\Desktop\ASCLogs-$((Get-Date).ToString('MM-dd-yyyy')) " -Force
$cred = Get-Credential -Credential Administrator
foreach ($server in $servers){

    if (Test-Connection -ComputerName $server -Count 1 -Quiet){
        $logpath = "\\$server\C$"
        $parameters = @{
            Name = "ASC"
            PSProvider = "FileSystem"
            Root = $logpath
            Credential = $cred } 
        New-PSDrive @parameters -ErrorAction SilentlyContinue -ErrorVariable crederr
            if (!$crederr){
                 $src = "ASC:\Program Files (x86)\ASC\ASC Product Suite\logs\"
                 Get-ChildItem $src |
                 % { Get-ChildItem $_.FullName } | % {if (($_.LastWriteTime -gt $StartTime) -and  ($_.LastWriteTime -lt $EndTime)) {
            $directoryName = ($_.DirectoryName).Replace("$logpath\Program Files (x86)\ASC\ASC Product Suite\logs\","")
            New-Item -ItemType Directory -Path $dst/$server/$directoryName -Force
            Copy-Item -Path $_.FullName -Destination "$dst/$server/$directoryName" -Force
            }        
          }
                Copy-Item "ASC:\Program Files (x86)\ASC\ASC Product Suite\Updater\config\target.xml" -Destination "$dst/$server/" -Force
                Copy-Item -Path "ASC:\Program Files (x86)\ASC\ASC Product Suite\data\" -Destination "$dst\$server\data" -Recurse -Force
                 Remove-PSDrive -Name ASC
            }else {
                    Write-Host "cannot access logs. Incorrect password entered for $server"
                    }
    }else {
            write-host "connection to $server failed"
            }
}
Compress-Archive -Path $dst -DestinationPath $dst -Force
Remove-Item $dst -Recurse
#End

