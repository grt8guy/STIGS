<#
.SOURCE: N/A

.SCOPE: VMware ESXi 7.0.3 {PowerCLI and Grep} STIG Compliancy Checker

.AUTHOR: John W. Braunsdorf
        
.DATE: 05/05/2021

.MODIFIED: 04/20/2023

#>

#region begins | Login information

$remoteHost = ""
$login = ""
$passwd = ''

Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false

Connect-VIServer -Server $remoteHost -User $login -Password $passwd

$vmhost = Get-VMHost -Name $remoteHost

$esxcli = Get-EsxCli -V2

$date = Get-Date

#Device Parameters
$Name =  $esxcli.system.hostname.get.Invoke() | Select HostName
$IPAddress = Get-VMHostNetworkAdapter -VMKernel | Select IP
$Mac = Get-VMHostNetworkAdapter -VMKernel | Select Mac
$FQDN = Get-VMHost | select Name

### clear console screen
Clear Screen

#endregion

Start-Sleep 2

#region begins | DOD Stig Check for ESXi 7.0.3

Write-Host "VMware vSphere 7.0 ESXi Security Technical Implementation Guide :: Version 1, Release: 1 Benchmark Date: 07 Mar 2023" -BackgroundColor Black -ForegroundColor Green
Write-Host $date -BackgroundColor Black -ForegroundColor Green

#endregion

Start-Sleep 2

#region begins - Stig Computer Field Info (Name,IPAddress,Mac,FQDN)

Write-Host "STIG Required Variables" -BackgroundColor Black -ForegroundColor Green
$Name | Format-Table -AutoSize
$IPAddress | Format-Table -AutoSize
$Mac | Format-Table -AutoSize
$FQDN | Format-Table -AutoSize

#endregion

Clear Screen
Write-Host "Starting Part 1 of PowerCLI Stig ESXi Checker" -BackgroundColor Black -ForegroundColor Green
Start-Sleep 2

#region begins Part-1 | PowerCli Commands

Write-Host "Vul ID: V-256375	   	Rule ID: SV-256375r885906_rule	   	STIG ID: ESXI-70-000001" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost  | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}} | Format-Table -AutoSize

Write-Host "Vul ID: V-256376	   	Rule ID: SV-256376r885909_rule	   	STIG ID: ESXI-70-000002	" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Format-Table -AutoSize

Write-Host "Vul ID: V-256377	   	Rule ID: SV-256377r885912_rule	   	STIG ID: ESXI-70-000003" -BackgroundColor White -ForegroundColor Blue $remoteHost
$remoteHost = Get-VMHost | Get-View
$lockdown = Get-View $remoteHost.ConfigManager.HostAccessManager
$lockdown.QueryLockdownExceptions()

Write-Host "Vul ID: V-256378	   	Rule ID: SV-256378r885915_rule	   	STIG ID: ESXI-70-000004	" -BackgroundColor White -ForegroundColor Blue $remoteHost	   
Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Format-Table -AutoSize

Write-Host "Vul ID: V-256379	   	Rule ID: SV-256379r885918_rule	   	STIG ID: ESXI-70-000005	" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Format-Table -AutoSize

Write-Host "Vul ID: V-256380	   	Rule ID: SV-256380r885921_rule	   	STIG ID: ESXI-70-000006" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Format-Table -AutoSize

Write-Host "Vul ID: V-256381	   	Rule ID: SV-256381r885924_rule	   	STIG ID: ESXI-70-000007" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Format-Table -AutoSize

Write-Host "Vul ID: V-256382	   	Rule ID: SV-256382r885927_rule	   	STIG ID: ESXI-70-000008" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue | Format-Table -AutoSize

#endregion

Write-Host "Starting Part 1 of Grep CLI Stig ESXi Checker" -BackgroundColor Black -ForegroundColor Green
Start-Sleep 2

#region begins Part-1 | GREP CLI

### remoteHost Host ###
$remoteHost = ""

### Varibables for PLink account
$login = ""
$passwd = ''

function plink
{
  [CmdletBinding()]
  PARAM
  (
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $remoteHost,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $login,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $passwd,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [string] $command)

  & echo Y |C:\temp\software\putty\plink.exe -ssh $remoteHost -l $login -pw $passwd $command

  return
}

Start-Sleep 2

### Grep "STIg" Commands
Write-Host "Vul ID: V-256383	   	Rule ID: SV-256383r885930_rule	   	STIG ID: ESXI-70-000009" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^Banner" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239267	   	Rule ID: SV-239267r674730_rule	   	STIG ID: ESXI-67-000010" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^FipsMode" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-256385	   	Rule ID: SV-256385r885936_rule	   	STIG ID: ESXI-70-000012" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^IgnoreRhosts" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-256386	   	Rule ID: SV-256386r885939_rule	   	STIG ID: ESXI-70-000013" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239270	   	Rule ID: SV-239270r674739_rule	   	STIG ID: remoteHost-67-000014" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^PermitRootLogin" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239271	   	Rule ID: SV-239271r674742_rule	   	STIG ID: remoteHost-67-000015" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239272	   	Rule ID: SV-239272r674745_rule	   	STIG ID: remoteHost-67-000016" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239273	   	Rule ID: SV-239273r674748_rule	   	STIG ID: remoteHost-67-000018" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^GSSAPIAuthentication" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239274	   	Rule ID: SV-239274r674751_rule	   	STIG ID: remoteHost-67-000019" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^KerberosAuthentication" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 10

Write-Host "Vul ID: V-239275	   	Rule ID: SV-239275r674754_rule	   	STIG ID: remoteHost-67-000020" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^StrictModes" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 10

Write-Host "Vul ID: V-239276	   	Rule ID: SV-239276r674757_rule	   	STIG ID: remoteHost-67-000021" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^Compression" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239277	   	Rule ID: SV-239277r674760_rule	   	STIG ID: remoteHost-67-000022" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^GatewayPorts" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239278	   	Rule ID: SV-239278r674763_rule	   	STIG ID: remoteHost-67-000023" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^X11Forwarding" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239279	   	Rule ID: SV-239279r674766_rule	   	STIG ID: remoteHost-67-000024" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^AcceptEnv" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239280	   	Rule ID: SV-239280r674769_rule	   	STIG ID: remoteHost-67-000025" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^PermitTunnel" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239281	   	Rule ID: SV-239281r674772_rule	   	STIG ID: remoteHost-67-000026" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239282	   	Rule ID: SV-239282r674775_rule	   	STIG ID: remoteHost-67-000027" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^ClientAliveInterval" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239283	   	Rule ID: SV-239283r674778_rule	   	STIG ID: remoteHost-67-000028" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^MaxSessions" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

write-host "Vul ID: V-239284	   	Rule ID: SV-239284r674781_rule	   	STIG ID: remoteHost-67-000029" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'cat /etc/ssh/keys-root/authorized_keys' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239288	   	Rule ID: SV-239288r674793_rule	   	STIG ID: remoteHost-67-000033" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^password" /etc/pam.d/passwd | grep sufficient' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

Write-Host "Vul ID: V-239331	   	Rule ID: SV-239331r674922_rule	   	STIG ID: remoteHost-67-100010" -BackgroundColor White -ForegroundColor Blue $remoteHost
plink -remoteHost $remoteHost -login $login -passwd $passwd -command 'grep -i "^Ciphers" /etc/ssh/sshd_config' | Write-Host -ForegroundColor Cyan

Start-Sleep 5

#endregion

Write-Host "Starting Part 2 of PowerCLI Stig ESXi Checker" -BackgroundColor Black -ForegroundColor Green
Start-Sleep 5 

#region begins Part-2 | PowerCli Commands
Write-Host "Vul ID: V-256396	   	Rule ID: SV-256396r885969_rule	   	STIG ID: ESXI-70-000030" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256397	   	Rule ID: SV-256397r885972_rule	   	STIG ID: ESXI-70-000031" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256398	   	Rule ID: SV-256398r885975_rule	   	STIG ID: ESXI-70-000032" -BackgroundColor White -ForegroundColor Blue $remoteHost	
Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256399	   	Rule ID: SV-256399r885978_rule	   	STIG ID: ESXI-70-000034" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256400	   	Rule ID: SV-256400r885981_rule	   	STIG ID: ESXI-70-000035" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}

Start-Sleep 2

Write-Host "Vul ID: V-256401	   	Rule ID: SV-256401r885984_rule	   	STIG ID: ESXI-70-000036" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"}

Start-Sleep 2

Write-Host "Vul ID: V-256402	   	Rule ID: SV-256402r885987_rule	   	STIG ID: ESXI-70-000037	" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostAuthentication 

Start-Sleep 2

Write-Host "Vul ID: V-256403	   	Rule ID: SV-256403r885990_rule	   	STIG ID: ESXI-70-000038	" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` 
@{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}} | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256404	   	Rule ID: SV-256404r885993_rule	   	STIG ID: ESXI-70-000039" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256405	   	Rule ID: SV-256405r885996_rule	   	STIG ID: ESXI-70-000041" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256406	   	Rule ID: SV-256406r885999_rule	   	STIG ID: ESXI-70-000042" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256407	   	Rule ID: SV-256407r886002_rule	   	STIG ID: ESXI-70-000043" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-239299	   	Rule ID: SV-239299r674826_rule	   	STIG ID: ESXI-67-000044" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.coredump.partition.get.Invoke() | Format-Table -AutoSize
$esxcli.system.coredump.network.get.Invoke() | Format-Table -AutoSize

$esxcli = Get-EsxCli -v2
#View available partitions to configure
$esxcli.system.coredump.partition.list.Invoke()

Start-Sleep 2

Write-Host "Vul ID: V-256408	   	Rule ID: SV-256408r886005_rule	   	STIG ID: ESXI-70-000045" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256409	   	Rule ID: SV-256409r886008_rule	   	STIG ID: ESXI-70-000046" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostNTPServer | Format-Table -AutoSize
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256410	   	Rule ID: SV-256410r886011_rule	   	STIG ID: ESXI-70-000047	" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.software.acceptance.get.Invoke() | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256411	   	Rule ID: SV-256411r886014_rule	   	STIG ID: ESXI-70-000048" -BackgroundColor White -ForegroundColor Blue $remoteHost
Write-Host "Validating vMotion Network" -BackgroundColor White -ForegroundColor Blue
# Get-VMHostNetworkAdapter -VMHost $remoteHost -VMKernel | Where-Object {$_.Name -eq 'vmk2'}
Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.Name -eq 'vmk2'}
Write-Host "vmk2 is usually setup for vMotion Network" -BackgroundColor White -ForegroundColor Blue

Start-Sleep 2

Write-Host "Vul ID: V-256412	   	Rule ID: SV-256412r886017_rule	   	STIG ID: ESXI-70-000049	" -BackgroundColor White -ForegroundColor Blue $remoteHost
Write-Host "Validating Management Network" -BackgroundColor White -ForegroundColor Blue
# Get-VMHostNetworkAdapter -VMHost $remoteHost -VMKernel | Where-Object {$_.Name -eq 'vmk0'}
Get-VMHostNetworkAdapter -VMKernel | Where-Object {$_.Name -eq 'vmk1'}
Write-Host "vmk0 is setup for Management Network Only" -BackgroundColor White -ForegroundColor Blue

Start-Sleep 2

Write-Host "Vul ID: V-256413	   	Rule ID: SV-256413r886020_rule	   	STIG ID: ESXI-70-000050" -BackgroundColor White -ForegroundColor Blue $remoteHost
Write-Host "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic." -BackgroundColor White -ForegroundColor Blue
Write-Host "IP Based storage is NOT used in this environment." -BackgroundColor White -ForegroundColor Blue

Start-Sleep 2

Write-Host "Vul ID: V-256414	   	Rule ID: SV-256414r886023_rule	   	STIG ID: ESXI-70-000053" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHostSnmp | Select *
# or 
# $esxcli.system.snmp.get.Invoke() | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256415	   	Rule ID: SV-256415r886026_rule	   	STIG ID: ESXI-70-000054	" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties

Start-Sleep 2

Write-Host "Vul ID: V-256416	   	Rule ID: SV-256416r886029_rule	   	STIG ID: ESXI-70-000055" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256417	   	Rule ID: SV-256417r886032_rule	   	STIG ID: ESXI-70-000056" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostFirewallException | Where {$_.Enabled -eq $true} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}} | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256418	   	Rule ID: SV-256418r886035_rule	   	STIG ID: ESXI-70-000057" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHostFirewallDefaultPolicy | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256419	   	Rule ID: SV-256419r886038_rule	   	STIG ID: ESXI-70-000058" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU

Start-Sleep 2

Write-Host "Vul ID: V-256420	   	Rule ID: SV-256420r886041_rule	   	STIG ID: ESXI-70-000059" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VirtualSwitch | Get-SecurityPolicy | Format-Table -AutoSize
Get-VirtualPortGroup | Get-SecurityPolicy | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256421	   	Rule ID: SV-256421r886044_rule	   	STIG ID: ESXI-70-000060" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VirtualSwitch | Get-SecurityPolicy | Format-Table -AutoSize
Get-VirtualPortGroup | Get-SecurityPolicy | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256422	   	Rule ID: SV-256422r886047_rule	   	STIG ID: ESXI-70-000061" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VirtualSwitch | Get-SecurityPolicy | Format-Table -AutoSize
Get-VirtualPortGroup | Get-SecurityPolicy | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256423	   	Rule ID: SV-256423r886050_rule	   	STIG ID: ESXI-70-000062" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256424	   	Rule ID: SV-256424r886053_rule	   	STIG ID: ESXI-70-000063" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VirtualPortGroup | Select Name, VLanID

Start-Sleep 2

Write-Host "Vul ID: V-256425	   	Rule ID: SV-256425r886056_rule	   	STIG ID: ESXI-70-000064" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VirtualPortGroup | Select Name, VLanID

Start-Sleep 2

Write-Host "Vul ID: V-256426	   	Rule ID: SV-256426r886059_rule	   	STIG ID: ESXI-70-000065" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VirtualPortGroup | Select Name, VLanID

Start-Sleep 2

Write-Host "Vul ID: V-256427	   	Rule ID: SV-256427r886062_rule	   	STIG ID: ESXI-70-000070" -BackgroundColor White -ForegroundColor Blue $remoteHost
Write-Host "All acounts and or Groups have the appropriate Access Levels" -BackgroundColor White -ForegroundColor Blue

Start-Sleep 2

Write-Host "Vul ID: V-256428	   	Rule ID: SV-256428r886065_rule	   	STIG ID: ESXI-70-000072" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli.system.version.get.Invoke()

Start-Sleep 2

Write-Host "Vul ID: V-256429	   	Rule ID: SV-256429r886068_rule	   	STIG ID: ESXI-70-000074" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256430	   	Rule ID: SV-256430r886071_rule	   	STIG ID: ESXI-70-000076" -BackgroundColor White -ForegroundColor Blue $remoteHost
Write-Host "Validate Hardware platform to validate ESXi host must enable Secure Boot" -BackgroundColor White -ForegroundColor Blue
Write-Host "HPe Blade must be Gen 9 and or higher to enable Secure Boot" -BackgroundColor White -ForegroundColor Blue
# /usr/lib/vmware/secureboot/bin/secureBoot.py -s
$esxcli.hardware.platform.get.Invoke() | select VendorName, ProductName,EnclosureSerialNumber,SerialNumber | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256431	   	Rule ID: SV-256431r886074_rule	   	STIG ID: ESXI-70-000078" -BackgroundColor White -ForegroundColor Blue $remoteHost
Write-Host "The ESXi host must use DoD-approved certificates" -BackgroundColor White -ForegroundColor Blue
Write-Host "The ESXi host uses VMWare self-signed certificates, which are generated from vCenter. This is a known issue to DoD. The vendor has not provided a resolution.  " -BackgroundColor White -ForegroundColor Blue

Start-Sleep 2

Write-Host "Vul ID: V-256432	   	Rule ID: SV-256432r886077_rule	   	STIG ID: ESXI-70-000079" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256433	   	Rule ID: SV-256433r886080_rule	   	STIG ID: ESXI-70-000081" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256435	   	Rule ID: SV-256435r886086_rule	   	STIG ID: ESXI-70-000083" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256436	   	Rule ID: SV-256436r886089_rule	   	STIG ID: ESXI-70-000084" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.auditrecords.get.invoke()|Format-List

Start-Sleep 2

Write-Host "Vul ID: V-256437	   	Rule ID: SV-256437r886092_rule	   	STIG ID: ESXI-70-000085" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.syslog.config.get.invoke()|Select StrictX509Compliance

Start-Sleep 2

Write-Host "Vul ID: V-256438	   	Rule ID: SV-256438r886095_rule	   	STIG ID: ESXI-70-000086" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.syslog.config.get.invoke()|Select StrictX509Compliance

Start-Sleep 2

Write-Host "Vul ID: V-256439	   	Rule ID: SV-256439r886098_rule	   	STIG ID: ESXI-70-000087" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Mem.MemEagerZero | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256440	   	Rule ID: SV-256440r886101_rule	   	STIG ID: ESXI-70-000088" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.vmacore.soap.sessionTimeout | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256441	   	Rule ID: SV-256441r886104_rule	   	STIG ID: ESXI-70-000089" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256442	   	Rule ID: SV-256442r886107_rule	   	STIG ID: ESXI-70-000090" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.security.fips140.rhttpproxy.get.invoke()

Start-Sleep 2

Write-Host "Vul ID: V-256443	   	Rule ID: SV-256443r886110_rule	   	STIG ID: ESXI-70-000091" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Format-Table -AutoSize

Start-Sleep 2

Write-Host "Vul ID: V-256446	   	Rule ID: SV-256446r886119_rule	   	STIG ID: ESXI-70-000094" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.settings.encryption.get.invoke() | Select Mode

Start-Sleep 2

Write-Host "Vul ID: V-256447	   	Rule ID: SV-256447r886122_rule	   	STIG ID: ESXI-70-000095" -BackgroundColor White -ForegroundColor Blue $remoteHost
$esxcli = Get-EsxCli -v2
$esxcli.system.settings.encryption.get.invoke() | Select RequireSecureBoot

Start-Sleep 2

Write-Host "Vul ID: V-256448	   	Rule ID: SV-256448r886125_rule	   	STIG ID: ESXI-70-000097" -BackgroundColor White -ForegroundColor Blue $remoteHost
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Format-Table -AutoSize

Start-Sleep 2

#endregion

Start-Sleep 5

#region begins - Clear All VI sessions and password files

### Disconnecting ALL VI Sessions
Write-Host "Closing All Active VI Connections" -BackgroundColor White -ForegroundColor Blue $remoteHost
Disconnect-VIServer -Server *.* -Force -Confirm:$false

Start-Sleep 2

Write-Host "All VI Sessions have been closed" -BackgroundColor Black -ForegroundColor Green

#endregion
