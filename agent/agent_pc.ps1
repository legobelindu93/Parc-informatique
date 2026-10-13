
param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("standalone","push")]
    [string]$Mode = "standalone",
    [Parameter(Mandatory=$false)]
    [string]$ServerUrl = "http://127.0.0.1:5000",
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = $env:TEMP,
    [Parameter(Mandatory=$false)]
    [switch]$VerboseMode = $false
)

if ($env:SRV) { $ServerUrl = $env:SRV; $Mode = "push" }
$Version = "5.1"
$startTime = Get-Date
$alerts = @{};$eolDb=@();$blacklist=@()
$eolDb=@('Windows 7','Windows 8','Windows 8.1','Windows Server 2008','Windows Server 2012','Office 2007','Office 2010','Office 2013','Office 2016','Adobe Flash','Adobe Shockwave','Java 6','Java 7','Java 8','Python 2.7','Internet Explorer 8','Internet Explorer 9','Internet Explorer 10','Internet Explorer 11','Silverlight','Windows Live','Windows Essentials','.NET Framework 4.5','.NET Framework 4.6.1')
$blacklist=@('Tor Browser','uTorrent','BitTorrent','Mimikatz','Burp Suite','Metasploit','Proxifier')

function Parse-SystemInfo {
    $info=@{};try{$raw=systeminfo /FO CSV /NH 2>$null;if($raw){$csv=($raw -join"`n")|ConvertFrom-Csv;$info=$csv[0]}}catch{}
    if(-not$info){try{$raw=systeminfo /FO LIST /NH 2>$null;if($raw){$h=@{}
        $raw|ForEach-Object{if($_ -match'^([^:]+):\s*(.*)'){$h[$matches[1].Trim()]=$matches[2].Trim()}};$info=[PSCustomObject]$h}}catch{}}
    $info
}

$ErrorActionPreference="SilentlyContinue"

Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  AGENT COLLECTE PARC v$Version ANSSI" -ForegroundColor Cyan
Write-Host "  Mode: $Mode" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Cyan

Write-Host "[1/13] Identite..." -NoNewline
$id=@{};$id.nom=$env:COMPUTERNAME
try{$w=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop;$id.fabricant=$w.Manufacturer;$id.modele=$w.Model;$id.domaine=$w.Domain;$id.type_machine=if($w.Model-match'Virtual|VMware|VirtualBox|Hyper-V|Xen'){'VM'}else{'Physique'}}catch{try{$w=Get-WmiObject Win32_ComputerSystem -ErrorAction Stop;$id.fabricant=$w.Manufacturer;$id.modele=$w.Model;$id.domaine=$w.Domain;$id.type_machine=if($w.Model-match'Virtual|VMware|VirtualBox|Hyper-V|Xen'){'VM'}else{'Physique'}}catch{$id.fabricant='';$id.modele='';$id.type_machine=''}}
# Detection domaine : CIM > WMI > USERDNSDOMAIN > USERDOMAIN
if([string]::IsNullOrEmpty($id.domaine)){$id.domaine=if($env:USERDNSDOMAIN){$env:USERDNSDOMAIN}else{$env:USERDOMAIN}}
try{$b=Get-CimInstance Win32_BIOS -ErrorAction Stop;$id.bios_serial=$b.SerialNumber;$id.bios_version=$b.SMBIOSBIOSVersion}catch{try{$b=Get-WmiObject Win32_BIOS -ErrorAction Stop;$id.bios_serial=$b.SerialNumber;$id.bios_version=$b.SMBIOSBIOSVersion}catch{$id.bios_serial='';$id.bios_version=''}}
try{$cp=Get-CimInstance Win32_ComputerSystemProduct -ErrorAction Stop;$id.uuid=$cp.UUID}catch{try{$cp=Get-WmiObject Win32_ComputerSystemProduct -ErrorAction Stop;$id.uuid=$cp.UUID}catch{$id.uuid=''}}
# Detection MAC/IP/type : Get-NetRoute > Get-NetAdapter > WMI/CIM > ipconfig (fallback robuste)
$mac='';$ip='';$wifi=''
try{$rt=Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop|Select-Object -First1;if($rt){$ai=(Get-NetAdapter -ifIndex $rt.InterfaceIndex -ErrorAction SilentlyContinue);if($ai-and$ai.MacAddress){$mac=$ai.MacAddress;$ip=(Get-NetIPAddress -InterfaceIndex $rt.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue|Select-Object -First1).IPAddress;$wifi=if($ai.InterfaceDescription-match'(?i)Wi-Fi|Wireless|802\.11'){'Wi-Fi'}else{'Ethernet'}}}}catch{}
if(-not$mac){try{$allNet=Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop|Where-Object{$_.IPEnabled -and $_.MACAddress};$phys=$allNet|Where-Object{$_.DefaultIPGateway}|Select-Object -First1;if(-not$phys){$phys=$allNet|Select-Object -First1};if($phys){$mac=$phys.MACAddress;$ip=$phys.IPAddress[0];$wifi=if($phys.Description-match'(?i)Wi-Fi|Wireless|802\.11'){'Wi-Fi'}else{'Ethernet'}}else{$mac='';$ip='';$wifi=''}}catch{$mac='';$ip='';$wifi=''}}
if(-not$mac){try{$mac=(Get-NetAdapter -ErrorAction Stop|Where-Object{$_.Status -eq 'Up' -and $_.MacAddress}|Select-Object -First1).MacAddress}catch{try{$mac=(Get-WmiObject Win32_NetworkAdapter -ErrorAction Stop|Where-Object{$_.NetEnabled -and $_.MACAddress}|Select-Object -First1).MACAddress}catch{$mac=''}}}
if(-not$mac){try{$mac=(Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop|Where-Object{$_.IPEnabled}|Select-Object -First1).MACAddress}catch{}}
# Fallback ipconfig /all (fonctionne sur tous les Windows, locale-independant)
if(-not$mac){try{$line=ipconfig /all|Select-String -Pattern'(?i)(adresse\s*physique|physical\s*address|adresse\s*mac).*?([0-9A-F]{2}(?:-[0-9A-F]{2}){5})'|Select-Object -First1;if($line){$mac=$line.Matches[0].Groups[2].Value}}catch{}}
if(-not$ip){try{$ip=(ipconfig|Select-String -Pattern'IPv4.*: (\d+\.\d+\.\d+\.\d+)'|Select-Object -First1).Matches[0].Groups[1].Value}catch{$ip=''}}
if(-not$ip){try{$ip=[System.Net.Dns]::GetHostByName($env:COMPUTERNAME).AddressList|Where-Object{$_.AddressFamily-eq'InterNetwork'}|Select-Object -First 1 -ExpandProperty IPAddressToString}catch{}}
$id.ip=$ip;$id.mac=$mac;$id.type_reseau=$wifi
Write-Host " $($id.nom) IP:$ip domaine:$($id.domaine)" -ForegroundColor Green

Write-Host "[2/13] Systeme..." -NoNewline
$sys=@{} 
try{$os=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';$osN=$os.ProductName;$osV=$os.CurrentVersion;$osB=$os.CurrentBuild;$osD=$os.DisplayVersion;$osRI=$os.ReleaseId}catch{$osN='Windows';$osV='';$osB='';$osD='';$osRI=''}
try{$osVreal=(Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Version;if($osVreal){$osV=$osVreal}}catch{}
if($osB-ge22000-and$osN-match'Windows 10'){$osN='Windows 11'}
try{$inst=if($os.InstallDate){[DateTime]::ParseExact($os.InstallDate,'yyyyMMdd',$null).ToString('dd/MM/yyyy')}else{''}}catch{$inst=''}
try{$boot=(Get-CimInstance Win32_OperatingSystem).LastBootUpTime;$upJ=if($boot){[Math]::Round(((Get-Date)-$boot).TotalDays,1)}else{''};$upH=if($boot){[Math]::Round(((Get-Date)-$boot).TotalHours,1)}else{''}}catch{$upJ='';$upH=''}
try{$sbActif=if((Confirm-SecureBootUEFI -ErrorAction Stop)){$true}else{$false}}catch{$sbActif=$false}
try{$firm=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction Stop;if($firm.PEFirmwareType-eq2){$uefi='UEFI'}else{$uefi='Legacy'}}catch{$uefi=''}
try{$edition=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction Stop).EditionID}catch{$edition=''}
try{$sku=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction Stop).InstallationType}catch{$sku=''}
$hotfixes=@();try{Get-HotFix -ErrorAction Stop|ForEach-Object{$hotfixes+=@{kb=$_.HotFixID;date=$_.InstalledOn.ToString('dd/MM/yyyy')}}}catch{}
$sys=@{nom=$osN;version=$osV;build=$osB;display_version=$osD;release_id=$osRI;arch=$env:PROCESSOR_ARCHITECTURE;edition=$edition;sku=$sku;date_installation=$inst;dernier_demarrage_j=$upJ;dernier_demarrage_h=$upH;secure_boot=$sbActif;uefi=$uefi;hotfixes=$hotfixes}
Write-Host " $osN" -ForegroundColor Green

Write-Host "[3/13] Materiel..." -NoNewline
$hw=@{};$cN='';$cC=[Environment]::ProcessorCount;$cL=[Environment]::ProcessorCount;$cM='';$cS=''
try{$cpu=Get-CimInstance Win32_Processor -ErrorAction Stop|Select-Object -First1;$cN=$cpu.Name;$cC=$cpu.NumberOfCores;$cL=$cpu.NumberOfLogicalProcessors;$cM=$cpu.MaxClockSpeed;$cS=$cpu.SocketDesignation}catch{try{$cpu=Get-WmiObject Win32_Processor -ErrorAction Stop|Select-Object -First1;$cN=$cpu.Name;$cC=$cpu.NumberOfCores;$cL=$cpu.NumberOfLogicalProcessors;$cM=$cpu.MaxClockSpeed;$cS=$cpu.SocketDesignation}catch{}}
try{$ramT=[Math]::Round((Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory/1GB,1)}catch{try{$ramT=[Math]::Round((Get-WmiObject Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory/1GB,1)}catch{$ramT=0}}
try{$ramU=[Math]::Round(((Get-Process|Measure-Object WorkingSet -Sum).Sum)/1MB,0)}catch{$ramU=0}
$disks=@()
try{Get-CimInstance Win32_LogicalDisk -Filter 'DriveType = 3' -ErrorAction Stop|ForEach-Object{$d=$_;try{$bl=$false;try{$bl=if(Get-BitLockerVolume -MountPoint $d.DeviceID -ErrorAction Stop){$true}}catch{};try{$dt='';$dk=Get-CimInstance Win32_DiskDrive -ErrorAction Stop|Where-Object{$_.DeviceID-eq((Get-CimInstance Win32_LogicalDiskToPartition -ErrorAction Stop|Where-Object{$_.Dependent-like"*$($d.DeviceID.replace(':',''))*"}|Select-Object -First1).Antecedent.Split(',')[0].Split('=')[1].trim('"'))};if($dk-and($dk.MediaType-like"*SSD*"-or$dk.Caption-like"*SSD*"-or$dk.Model-like"*SSD*"-or$dk.Caption-like"*NVMe*"-or$dk.Model-like"*NVMe*")){$dt='SSD'}else{$dt='HDD'}}catch{$dt=''};$disks+=@{lettre=$d.DeviceID;type=$dt;taille_gb=[Math]::Round($d.Size/1GB,1);libre_gb=[Math]::Round($d.FreeSpace/1GB,1);pct_libre=[Math]::Round($d.FreeSpace/$d.Size*100,1);bitlocker=$bl}}catch{}}}catch{try{Get-WmiObject Win32_LogicalDisk -Filter'DriveType=3'|ForEach-Object{$d=$_;try{$bl=$false;try{$bl=if(Get-BitLockerVolume -MountPoint $d.DeviceID -ErrorAction Stop){$true}}catch{};try{$dt='';$dk=Get-WmiObject Win32_DiskDrive -ErrorAction Stop|Where-Object{$_.DeviceID-eq((Get-WmiObject Win32_LogicalDiskToPartition -ErrorAction Stop|Where-Object{$_.Dependent-like"*$($d.DeviceID.replace(':',''))*"}|Select-Object -First1).Antecedent.Split(',')[0].Split('=')[1].trim('"'))};if($dk-and($dk.MediaType-like"*SSD*"-or$dk.Caption-like"*SSD*"-or$dk.Model-like"*SSD*"-or$dk.Caption-like"*NVMe*"-or$dk.Model-like"*NVMe*")){$dt='SSD'}else{$dt='HDD'}}catch{$dt=''};$disks+=@{lettre=$d.DeviceID;type=$dt;taille_gb=[Math]::Round($d.Size/1GB,1);libre_gb=[Math]::Round($d.FreeSpace/1GB,1);pct_libre=[Math]::Round($d.FreeSpace/$d.Size*100,1);bitlocker=$bl}}catch{}}}catch{}}
try{$gpu=(Get-CimInstance Win32_VideoController -ErrorAction Stop|Select-Object -First1).Name;$gpuRAM=(Get-CimInstance Win32_VideoController -ErrorAction Stop|Select-Object -First1).AdapterRAM}catch{try{$gpu=(Get-WmiObject Win32_VideoController -ErrorAction Stop|Select-Object -First1).Name;$gpuRAM=(Get-WmiObject Win32_VideoController -ErrorAction Stop|Select-Object -First1).AdapterRAM}catch{$gpu='';$gpuRAM=''}}
try{$bat='Non';$batPct='';$batCheck=Get-CimInstance Win32_Battery -ErrorAction Stop;if($batCheck){$bat='Oui';$batPct=$batCheck.EstimatedChargeRemaining}}catch{try{$bat='Non';$batPct='';$batCheck=Get-WmiObject Win32_Battery -ErrorAction Stop;if($batCheck){$bat='Oui';$batPct=$batCheck.EstimatedChargeRemaining}}catch{}}
$hw=@{cpu=@{modele=$cN;coeurs=$cC;logiques=$cL;frequence_mhz=$cM;socket=$cS};ram=@{total_gb=$ramT;utilisation_mb=$ramU};disques=$disks;gpu=@{nom=$gpu;ram=$gpuRAM};batterie=@{presente=$bat;charge_pct=$batPct}}
# Fallback systeminfo pour les champs manquants
try{$si=Parse-SystemInfo
if($si){$siProps=$si.PSObject.Properties
if(-not$cN -and $siProps['Processor(s)']){$cN=($si.('Processor(s)')-split','|Select-Object -First1).Trim();$hw.cpu.modele=$cN}
if(-not$id.domaine -or $id.domaine -eq 'WORKGROUP'){$domVal=$null
    foreach($k in $siProps.Name){if($k -match'(?i)(domaine|domain)'){$domVal=$si.$k;break}}
    if($domVal -and $domVal -ne 'WORKGROUP'){$id.domaine=$domVal;Write-Host " (domaine:$domVal)" -NoNewline -ForegroundColor Yellow}}
if(-not$id.fabricant){foreach($k in $siProps.Name){if($k -match'(?i)(fabricant|manufacturer|system manufacturer)'){$id.fabricant=$si.$k;break}}}
if(-not$id.modele){foreach($k in $siProps.Name){if($k -match'(?i)(modele|model|system model)'){$id.modele=$si.$k;break}}}
if(-not$sys.nom){foreach($k in $siProps.Name){if($k -match'(?i)(os name|nom de l.os|nom du systeme)'){$sys.nom=$si.$k;break}}}
if(-not$hw.ram.total_gb){foreach($k in $siProps.Name){if($k -match'(?i)(total physical memory|memoire physique totale)'){$v=$si.$k-replace'[^\d,.]','';if($v){$v=$v-replace',','.';$hw.ram.total_gb=[Math]::Round([double]::Parse($v,[Globalization.CultureInfo]::InvariantCulture)/1GB,1)}}}}
if(-not$id.bios_version){foreach($k in $siProps.Name){if($k -match'(?i)(bios version|version bios)'){$id.bios_version=($si.$k -split',')[0].Trim();break}}}
if(-not$sys.date_installation){foreach($k in $siProps.Name){if($k -match'(?i)(original install date|date d.installation d.origine|date d.installation)'){$sys.date_installation=$si.$k;break}}}
}}catch{}
Write-Host " CPU:$cC coeurs RAM:${ramT}GB" -ForegroundColor Green

Write-Host "[4/13] Utilisateurs..." -NoNewline
$users=@{}
try{$loc=Get-LocalUser -ErrorAction Stop|ForEach-Object{$_.Name};$adm=(Get-LocalGroupMember -Group Administrateurs -ErrorAction Stop|ForEach-Object{$_.Name})}catch{$loc=@();$adm=@()}
$admActif=($adm -match [regex]::Escape($env:USERNAME)).Count -gt 0
try{$lastLogon=(Get-CimInstance Win32_NetworkLoginProfile -ErrorAction Stop|Sort-Object LastLogon -Descending|Select-Object -First1).LastLogon;if($lastLogon){$lastLogon=$lastLogon.ToString('dd/MM/yyyy')}}catch{$lastLogon=''}
$users=@{connecte=$env:USERNAME;locaux=$loc;admins=$adm;admin_actif=$admActif;derniere_connexion=$lastLogon}
Write-Host " $env:USERNAME (admin:$admActif)" -ForegroundColor Green

Write-Host "[5/13] Logiciels..." -NoNewline
$sw=@();$seen=@{};$eolSw=@();$nonAutorises=@();$pExes=@()
$cacheDir="$env:LOCALAPPDATA\InventaireParc"
if(-not(Test-Path $cacheDir)){New-Item -ItemType Directory -Path $cacheDir -Force|Out-Null}
$cacheFile="$cacheDir\full_cache.json";$fpFile="$cacheDir\fingerprint.txt"

function Compute-Fingerprint {
    $parts=@()
    try{$parts+=((Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -Name DisplayName -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName})|ForEach-Object{$_.DisplayName}) -join '|'}catch{}
    try{$parts+=((Get-ChildItem 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue|Get-ItemProperty -Name DisplayName -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName})|ForEach-Object{$_.DisplayName}) -join '|'}catch{}
    try{$parts+=((Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue|Get-ItemProperty -Name DisplayName -ErrorAction SilentlyContinue|Where-Object{$_.DisplayName})|ForEach-Object{$_.DisplayName}) -join '|'}catch{}
    try{$parts+=((Get-AppxPackage -ErrorAction SilentlyContinue|ForEach-Object{$_.Name+'='+$_.Version}) -join '|')}catch{}
    try{$parts+=((Get-ChildItem "$env:ProgramFiles","${env:ProgramFiles(x86)}","$env:ProgramData","$env:APPDATA" -Recurse -Depth 2 -Include '*.exe' -ErrorAction SilentlyContinue|ForEach-Object{$_.Name+'|'+$_.Length}) -join '||')}catch{}
    $hashBytes=[System.Text.Encoding]::UTF8.GetBytes($parts -join '|||')
    $sha=[System.Security.Cryptography.SHA256]::Create()
    return [Convert]::ToBase64String($sha.ComputeHash($hashBytes))
}

$fp=Compute-Fingerprint
$cachedFp=''
if(Test-Path $fpFile){$cachedFp=(Get-Content $fpFile -Raw -ErrorAction SilentlyContinue).Trim()}
$cacheValid=$cachedFp -and $cachedFp -eq $fp -and (Test-Path $cacheFile)

if($cacheValid){
    try{$cache=(Get-Content $cacheFile -Raw -ErrorAction SilentlyContinue|ConvertFrom-Json);$sw=@($cache.sw);$pExes=@($cache.pExes);$seen=@{};$sw|ForEach-Object{$nk=($_.nom.ToLower()-replace'\s+',' ')+'|'+($_.version-replace'\s+',' ')+'|'+($_.editeur-replace'\s+',' ');$seen[$nk]=$true};$eolSw=@();$nonAutorises=@();$sw|ForEach-Object{$n=$_.nom;$cat=$_.categorie;foreach($eol in $eolDb){if($n-match'(?<=^|[^a-z0-9])'+[regex]::Escape($eol)+'\b'){$script:eolSw+=$n}};foreach($b in $blacklist){if($n-match[regex]::Escape($b)){$script:nonAutorises+=$n}};if($n-match'\b(Crack|Keygen|Patch|Hack|Loader|Injection)\b'){$script:nonAutorises+=$n}};Write-Host " $($sw.Count) + $($pExes.Count) portables (cache)" -ForegroundColor Green;Write-Host " [6-13/13] (cache)" -NoNewline;Write-Host " OK" -ForegroundColor Green
    }catch{$cacheValid=$false}
}

if(-not$cacheValid){

function Add-Software($n,$v,$e,$p,$desc,$t,$c,$src,$sp,$insD,$arch,$hl,$sig,$h){
  if(-not$n){return}
  $nk=($n.ToLower() -replace'\s+',' ') + '|' + ($v -replace'\s+',' ') + '|' + ($e -replace'\s+',' ')
  if($seen.ContainsKey($nk)){return}
  $seen[$nk]=$true
  $eolF=$false;$cat=$c
  foreach($eol in $eolDb){if($n-match'(?<=^|[^a-z0-9])'+[regex]::Escape($eol)+'\b'){$eolF=$true}}
  if(-not$cat){
    if($n-match'\b(Office|Word|Excel|PowerPoint|Outlook|Access|Publisher)\b'){$cat='Bureautique'}
    elseif($n-match'\b(Chrome|Firefox|Edge|Opera|Brave|Safari|Chromium)\b'){$cat='Navigateur'}
    elseif($n-match'\b(Defender|Antivirus|Security|ESET|Kaspersky|Bitdefender|Avast|Norton|McAfee|Sophos|Malwarebytes|CrowdStrike|Sentinel|Trend Micro|Palo Alto)\b'){$cat='Securite'}
    elseif($n-match'\b(Visual Studio|VS Code|IntelliJ|Eclipse|PyCharm|Git|Docker|Python|Node|Java|JDK|JRE|\.NET|Ruby|PHP|Go|Rust|Cargo|WebStorm|JetBrains|CMake|MinGW)\b'){$cat='Developpement'}
    elseif($n-match'\b(Adobe|Photoshop|Illustrator|AutoCAD|SolidWorks|Blender|GIMP|Corel|InDesign|Premiere|After Effects|DaVinci|Figma|Canva)\b'){$cat='Creation'}
    elseif($n-match'\b(Teams|Slack|Discord|Zoom|Skype|Outlook|Telegram|WhatsApp|Messenger|Signal|Threema)\b'){$cat='Communication'}
    elseif($n-match'\b(7-Zip|WinRAR|Notepad\+\+|Sublime|Everything|Sumatra|DB Browser|PDF|Foxit|Adobe Reader|SumatraPDF|TreeSize|Ccleaner|Speccy|HWMonitor|CPU-Z|GPU-Z)\b'){$cat='Utilitaire'}
    elseif($n-match'\b(SQL Server|MySQL|MariaDB|PostgreSQL|MongoDB|Oracle|Redis|Elasticsearch|Cassandra|SQLite)\b'){$cat='BaseDonnees'}
    elseif($n-match'\b(VMware|VirtualBox|Hyper-V|Docker|Vagrant|WSL|Proxmox)\b'){$cat='Virtualisation'}
    elseif($n-match'\b(Dropbox|OneDrive|Google Drive|iCloud|Nextcloud|Synology|pCloud|Mega)\b'){$cat='Cloud'}
    elseif($n-match'\b(KeePass|Bitwarden|LastPass|Dashlane|1Password|NordPass|Keeper)\b'){$cat='MotsDePasse'}
    elseif($n-match'\b(VeraCrypt|Gpg4win|GnuPG|BitLocker|AxCrypt)\b'){$cat='Chiffrement'}
    elseif($n-match'\b(Proxifier|Charles|Burp|Postman|Insomnia|Fiddler|Wireshark|Nmap|Angry IP|Advanced IP)\b'){$cat='Reseau'}
    elseif($n-match'\b(TeamViewer|AnyDesk|VNC|RDP|Remote Desktop|SplashTop|LogMeIn)\b'){$cat='SupportDistant'}
    elseif($n-match'\b(Spod|Spotify|iTunes|Media Player|MPC|VLC|GOM|KMPlayer|PotPlayer)\b'){$cat='Multimedia'}
    elseif($n-match'\b(Veeam|Acronis|Backup|Backupexec|EaseUS|Macrium|AOMEI)\b'){$cat='Sauvegarde'}
    elseif($n-match'\b(Driver|Pilote|Intel|AMD|NVIDIA|Realtek)\b'){$cat='Pilote'}
    elseif($n-match'\b(SAP|Salesforce|Oracle CRM|Dynamics|Odoo|ERP|CRM)\b'){$cat='Gestion'}
    elseif($n-match'\b(Sysinternals|Process Explorer|Process Monitor|Autoruns|PsExec|Regedit)\b'){$cat='OutilsSysteme'}
    else{$cat='Logiciel'}
  }
  $risk='Faible';$riskScore=0
  if($eolF){$risk='Eleve';$riskScore=8;$script:eolSw+=$n}
  # Securite EOL → Critique (antivirus obsolete = risque majeur)
  if($eolF -and $cat -eq 'Securite'){$risk='Critique';$riskScore=10}
  foreach($b in $blacklist){if($n-match[regex]::Escape($b)){$risk='Critique';$riskScore=10;$script:nonAutorises+=$n}}
  if($n-match'\b(Crack|Keygen|Patch|Hack|Loader|Injection)\b'){$risk='Critique';$riskScore=10;$script:nonAutorises+=$n}
  # Installe il y a 2+ ans sans mise a jour → Moyen
  if($riskScore -lt 5 -and $insD -match'^(\d{2})/(\d{2})/(\d{4})$'){
    $insY=[int]$matches[3];$insM=[int]$matches[2]
    $nw=Get-Date;$age=($nw.Year-$insY)+($nw.Month-$insM)/12
    if($age -ge 2){$risk='Moyen';$riskScore=5}
  }
  $descRisk=if($riskScore-ge8){"Logiciel $risk detecte"}elseif($riskScore-ge5){"Logiciel obsolete (installe $insD)"}else{''}
  $script:sw+=@{nom=$n;version=$v;editeur=$e;chemin=$p;description=$desc;taille_kb=$t;date_installation=$insD;type=$sp;categorie=$cat;install_source=$src;install_lang='';architecture=$arch;editeur_url=$hl;url_help=$hl;risque_auto=$risk;risque_desc=$descRisk;risque_score=$riskScore;eol=if($eolF){'OUI'}else{'Non'};signature=$sig;portable=$false;hash_sha256=$h;cert_editeur='';dependances='';version_date='';build='';derniere_execution=''}
}

function Add-RegistryItems($path,$arch,$src,$includeSystem=$false){
  try{Get-ChildItem $path -ErrorAction SilentlyContinue|ForEach-Object{$k=Get-ItemProperty$_.PsPath
    $dn=$k.DisplayName;if(-not$dn){return}
    if(-not$includeSystem-and($k.SystemComponent-or$k.ParentKeyName)){return}
    $n=($dn-join'').Trim();if($n.Length-lt2){return}
    if($includeSystem-and$n-match'^(KB\d+|Update|Patch|Security|Hotfix|Service Pack|\{[\da-f\-]+\})'){return}
    $d='';if($k.InstallDate){$iv=($k.InstallDate-join'');if($iv-match'^(\d{4})(\d{2})(\d{2})$'){$d="$($matches[3])/$($matches[2])/$($matches[1])"}}
    $t='';if($k.EstimatedSize){$t=[Math]::Round($k.EstimatedSize/1KB,1)}
    Add-Software $n ($k.DisplayVersion-join'') ($k.Publisher-join'') ($k.InstallLocation-join'') '' $t '' $src '' $d $arch ($k.URLInfoAbout-join'') '' ''
  }}catch{}
}
Add-RegistryItems 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall' '64-bit' 'Registry'
Add-RegistryItems 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' '32-bit' 'Registry'
Add-RegistryItems 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall' '' 'Registry_HKCU'
Add-RegistryItems 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall' '64-bit' 'Registry' $true
Add-RegistryItems 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' '32-bit' 'Registry' $true
# Collect KB/Windows Updates (separate from filtered system components)
try{Get-ChildItem 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue|ForEach-Object{$k=Get-ItemProperty$_.PsPath;$dn=$k.DisplayName;if($dn-and$dn-match'^(KB\d+)'){$kb=$matches[1];$kbVer=$k.DisplayVersion;$kbPub=$k.Publisher;if($kbPub-eq''){$kbPub='Microsoft Corporation'};if(-not$seen.ContainsKey(($kb+$kbVer+$kbPub).ToLower())){Add-Software "$kb ($($k.Description))" $kbVer $kbPub '' 'Mise a jour Windows' '' '' 'WindowsUpdate' '' '' '' '' '' ''}}}}catch{}
try{Get-AppxPackage -ErrorAction SilentlyContinue|ForEach-Object{$n=$_.Name;if($n-match'^[^\.]+\.[^\.]'){$dn=$n}else{$dn=$n};Add-Software $dn $_.Version $_.Publisher '' '' '' 'Store' 'Appx' '' '' '' '' '' ''}}catch{}
try{Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue|ForEach-Object{$k=$_.DisplayName+'|'+$_.DisplayVersion;if(-not$seen.ContainsKey($k)){Add-Software $_.DisplayName $_.DisplayVersion 'Windows' '' '' '' 'Store' 'AppxProvisioned' '' '' '' '' '' ''}}}catch{}
try{$wgExe=Get-Command winget -ErrorAction SilentlyContinue;if($wgExe){
  $wgOut=&winget list --accept-source-agreements 2>&1|Out-String
  if($wgOut){$wgLines=$wgOut -split"`n"|Where-Object{$_-match'^\s*[\w\-\.]+\s+[\w\-\.]+\s+[\w\-\.]+\s+'}|Select-Object -Skip 2
    foreach($wgLine in $wgLines){if($wgLine-match'^\s*([\w\-\.\s]+?)\s{2,}([\w\-\.]+)\s{2,}([\w\-\.]+)'){$wn=$matches[1].Trim();$wv=$matches[2].Trim();$wid=$matches[3].Trim();if($wn-and$wn.Length-gt1-and$wn-notmatch'^(Nom|Name|$)'){Add-Software $wn $wv $wid '' '' '' '' 'Winget' '' '' '' '' '' ''}}}
  }
}}catch{}
try{if(Get-Command choco -ErrorAction SilentlyContinue){$ch=&choco list -r --limit-output 2>&1|Out-String;if($ch){$ch -split"`n"|ForEach-Object{$p=$_-split'\|';if($p[0]-and$p[1]-and$p[0].Length-gt1-and$p[0]-notmatch'^[0]'){Add-Software $p[0].Trim() $p[1].Trim() 'Chocolatey' '' '' '' '' 'Chocolatey' '' '' '' '' '' ''}}}}}catch{}
try{$pp=pip list --format=json 2>$null;if($pp){$pp|ConvertFrom-Json|ForEach-Object{Add-Software "pip: $($_.name)" $_.version 'Python' '' '' '' 'Developpement' 'pip' '' '' '' '' '' ''}}}catch{}
try{$np=npm list -g --depth=0 --json 2>$null;if($np){$npObj=$np|ConvertFrom-Json;if($npObj.dependencies){$npObj.dependencies.PSObject.Properties|ForEach-Object{Add-Software "npm: $($_.Name)" $_.Value.version 'Node.js' '' '' '' 'Developpement' 'npm' '' '' '' '' '' ''}}}}catch{}
# Start Menu shortcuts
try{@("$env:ProgramData\Microsoft\Windows\Start Menu","$env:APPDATA\Microsoft\Windows\Start Menu")|ForEach-Object{if(Test-Path $_){Get-ChildItem $_ -Recurse -Depth 4 -Include '*.lnk' -ErrorAction SilentlyContinue|ForEach-Object{$shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut($_.FullName);$tgt=$link.TargetPath;if($tgt-and$tgt-match'\.exe$'){$bn=[System.IO.Path]::GetFileName($tgt);if(-not$seen.ContainsKey($bn+'||')){try{$fv=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($tgt);$ver="$($fv.FileVersion)";$edt="$($fv.CompanyName)"}catch{$ver='';$edt=''};Add-Software $bn $ver $edt $tgt $link.Description '' '' 'StartMenu' '' '' '' '' '' ''}};$null=[System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$shell)}}}}catch{}
# Windows features/roles
try{$features=dism /online /get-features /format:table /quiet 2>&1|Out-String;if($features){$features -split"`n"|Where-Object{$_-match'^\|[\s\-]+\|'}|ForEach-Object{$parts=$_-split'\s*\|\s*';if($parts[1]-and$parts[1]-ne''-and$parts[2]-match'Enabled'){Add-Software "WindowsFeature: $($parts[1].Trim())" '' 'Microsoft' '' '' '' 'Utilitaire' 'WindowsFeature' '' '' '' '' '' ''}}}}catch{}
# PATH executables (capte les exe dans tous les dossiers PATH)
try{$env:Path -split';'|Where-Object{$_-and(Test-Path $_)}|Select-Object -Unique|ForEach-Object{$dir=$_;try{Get-ChildItem $dir -Include '*.exe','*.com','*.cmd','*.msi','*.ps1','*.bat','*.vbs','*.jar' -ErrorAction SilentlyContinue|ForEach-Object{$k=$_.Name+'||';if(-not$seen.ContainsKey($k)){$seen[$k]=$true;$ext=[System.IO.Path]::GetExtension($_.Name).ToLower();try{$fv=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName);$ver="$($fv.FileVersion)";$edt="$($fv.CompanyName)";$desc="$($fv.FileDescription)"}catch{$ver='';$edt='';$desc=''};Add-Software $_.Name $ver $edt $_.FullName $desc ([Math]::Round($_.Length/1KB)) '' 'PATH' $ext '' '' '' '' ''}}}catch{}}}catch{}
}
# Sauvegarde cache + portables
$pSeen=@{};$pPathsDeep=@("$env:ProgramFiles","${env:ProgramFiles(x86)}","$env:ProgramData","$env:APPDATA","$env:LOCALAPPDATA","C:\tools","C:\Dev","C:\laragon");$pPathsShallow=@("$env:USERPROFILE\Desktop","$env:USERPROFILE\Downloads","$env:USERPROFILE\Documents","$env:TEMP")
Write-Host " $($sw.Count) trouve(s)" -ForegroundColor Green

Write-Host "[6/13] Portables (scan profond)..." -NoNewline
if(-not$cacheValid){
$pExes=@();$pSeen=@{}
foreach($pp in $pPathsDeep){if(Test-Path $pp){try{Get-ChildItem $pp -Recurse -Depth 5 -Include '*.exe','*.com','*.msi','*.msp','*.msu','*.cab','*.appx','*.appxbundle','*.jar' -ErrorAction SilentlyContinue|ForEach-Object{if(-not$pSeen.ContainsKey($_.Name)-and$_.Name-notmatch'^(unins|uninstall|setup|install|vc_redist|vcredist|dotnet|NDP|symsrv)'){$pSeen[$_.Name]=$true;$ext=[System.IO.Path]::GetExtension($_.Name).ToLower();try{$sz=$_.Length}catch{$sz=0};try{$fv=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName);$ver="$($fv.FileVersion)";$edt="$($fv.CompanyName)";$desc="$($fv.FileDescription)";$prod="$($fv.ProductName)"}catch{$ver='';$edt='';$desc='';$prod=''};try{$sg=(Get-AuthenticodeSignature $_.FullName -ErrorAction Stop).Status}catch{$sg='Inconnu'};try{$h256=(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash;$h256}catch{$h256=''};try{$modif=$_.LastWriteTime.ToString('dd/MM/yyyy')}catch{$modif=''};try{$acces=$_.LastAccessTime.ToString('dd/MM/yyyy HH:mm')}catch{$acces=''};Add-Software $_.Name $ver $edt $_.FullName $desc ([Math]::Round($sz/1KB)) '' 'Portable' $ext $modif 'auto' '' $sg $h256;$pExes+=@{nom=$_.Name;chemin=$_.FullName;editeur=$edt;version=$ver;description=$desc;produit=$prod;signature=$sg;taille_kb=([Math]::Round($sz/1KB));hash_sha256=$h256;date_modification=$modif;derniere_execution=$acces}}}}catch{}}}
foreach($pp in $pPathsShallow){if(Test-Path $pp){try{Get-ChildItem $pp -Recurse -Depth 2 -Include '*.exe','*.com','*.msi','*.msp','*.msu','*.cab','*.appx','*.appxbundle','*.jar','*.ps1','*.bat','*.vbs' -ErrorAction SilentlyContinue|ForEach-Object{if(-not$pSeen.ContainsKey($_.Name)-and$_.Name-notmatch'^(unins|uninstall|setup|install|vc_redist|vcredist|dotnet|NDP|symsrv)'){$pSeen[$_.Name]=$true;$ext=[System.IO.Path]::GetExtension($_.Name).ToLower();try{$sz=$_.Length}catch{$sz=0};try{$fv=[System.Diagnostics.FileVersionInfo]::GetVersionInfo($_.FullName);$ver="$($fv.FileVersion)";$edt="$($fv.CompanyName)";$desc="$($fv.FileDescription)";$prod="$($fv.ProductName)"}catch{$ver='';$edt='';$desc='';$prod=''};try{$sg=(Get-AuthenticodeSignature $_.FullName -ErrorAction Stop).Status}catch{$sg='Inconnu'};try{$h256=(Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction Stop).Hash;$h256}catch{$h256=''};try{$modif=$_.LastWriteTime.ToString('dd/MM/yyyy')}catch{$modif=''};try{$acces=$_.LastAccessTime.ToString('dd/MM/yyyy HH:mm')}catch{$acces=''};Add-Software $_.Name $ver $edt $_.FullName $desc ([Math]::Round($sz/1KB)) '' 'Portable' $ext $modif 'auto' '' $sg $h256;$pExes+=@{nom=$_.Name;chemin=$_.FullName;editeur=$edt;version=$ver;description=$desc;produit=$prod;signature=$sg;taille_kb=([Math]::Round($sz/1KB));hash_sha256=$h256;date_modification=$modif;derniere_execution=$acces}}}}catch{}}}
try{($sw|ConvertTo-Json -Depth 5 -Compress)|Out-File $cacheFile -Encoding utf8;$fp|Out-File $fpFile -Encoding utf8}catch{}
Write-Host " $($pExes.Count)" -ForegroundColor Green
} else { Write-Host " $($pExes.Count) (cache)" -ForegroundColor Green }

Write-Host "[7/13] Enrichissement..." -NoNewline
if(-not$cacheValid){
$enriched=0
foreach($s in $sw){if($s.chemin-and$s.chemin-ne''-and(Test-Path $s.chemin)){
  try{$f=Get-Item $s.chemin -ErrorAction Stop
    try{$s.hash_sha256=(Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash;$enriched++}catch{}
    try{$cert=Get-AuthenticodeSignature $f.FullName -ErrorAction Stop;if($cert.Status-eq'Valid'){$s.cert_editeur=$cert.SignerCertificate.Subject;$s.signature='Valide';$enriched++}}catch{}
    try{$s.derniere_execution=$f.LastWriteTime.ToString('dd/MM/yyyy HH:mm')}catch{}
    try{$s.version_date=$f.CreationTime.ToString('dd/MM/yyyy')}catch{}
  }catch{}
}}
Write-Host " $enriched enrichis" -ForegroundColor Green
} else { Write-Host " (cache)" -ForegroundColor Green }

if(-not$cacheValid){
# WSL distributions
try{$wsl=wsl -l -q 2>$null;if($wsl){$wsl -split"`n"|Where-Object{$_-and$_-notmatch'Windows'}|ForEach-Object{$d=$_.Trim();if($d){Add-Software "WSL: $d" '' 'Microsoft' '' "WSL Linux distribution: $d" '' '' 'WSL' '' '' '' '' '' ''}}}}catch{}
# PHP/Composer globals
try{$comp=cmd /c 'composer global show 2>nul' 2>$null;if($comp){$comp|Where-Object{$_-match'^([\w\-\.\/]+)\s+([\w\-\.]+)'}|ForEach-Object{if($_ -match'^([\w\-\.\/]+)\s+v?([\w\-\.]+)'){Add-Software "composer: $($matches[1])" $matches[2] '' '' '' '' 'Developpement' 'Composer' '' '' '' '' '' ''}}}}catch{}
}
Write-Host "[8/13] Securite..." -NoNewline
$sec=@{}
try{$def=Get-MpComputerStatus -ErrorAction Stop;$avActif=$def.AntivirusEnabled;$defActif=$def.AntivirusEnabled;$cg=if($def.CredentialGuardEnabled){$true}else{$false};$avSig=$def.AntivirusSignatureVersion;$avAge=$def.AntivirusSignatureAge;$avName=$def.AntivirusSignatureLastUpdated;$defVersion=$def.AMProductVersion;$defEngine=$def.AMEngineVersion;$defPlatform=$def.AMServiceVersion;$realTime=$def.RealTimeProtectionEnabled;$pua=$def.PUAProtection;$avUpToDate=if($avAge-le5){$true}else{$false}}catch{$avActif=$false;$defActif=$false;$cg=$false;$avSig='';$avAge='';$avName='';$defVersion='';$defEngine='';$defPlatform='';$realTime=$false;$pua='';$avUpToDate=$false}
try{$fw=Get-NetFirewallProfile -ErrorAction Stop;if($fw|Where-Object{$_.Enabled-eq$true}){$fwOk=$true;$fwProfiles=@($fw|Where-Object{$_.Enabled-eq$true}|ForEach-Object{$_.Name})}else{$fwOk=$false;$fwProfiles=@()}}catch{$fwOk=$false;$fwProfiles=@()}
try{$blVolumes=Get-BitLockerVolume -ErrorAction SilentlyContinue -WarningAction SilentlyContinue;$blCount=@($blVolumes).Count;$blProtected=@($blVolumes|Where-Object{$_.ProtectionStatus-eq1}).Count}catch{$blCount=0;$blProtected=0}
if(-not$blCount){try{$blSvc=Get-Service BDESVC -ErrorAction Stop;if($blSvc.Status-eq'Running'){$blCount=1}}catch{}}
try{$asr=if((Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids){$true;$asrRules=@(Get-MpPreference -ErrorAction Stop).AttackSurfaceReductionRules_Ids}else{$false;$asrRules=@()}}catch{$asr=$false;$asrRules=@()}
try{$wdac=if((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop).VirtualizationBasedSecurityStatus-eq2){$true}else{$false}}catch{$wdac=$false}
try{$avProd=Get-WmiObject -Namespace root\SecurityCenter2 -Class AntiVirusProduct -ErrorAction Stop;$avList=@($avProd|ForEach-Object{$_.displayName})}catch{$avList=@()}
try{$wl=Get-WmiObject -Namespace root\SecurityCenter2 -Class FirewallProduct -ErrorAction Stop;$fwList=@($wl|ForEach-Object{$_.displayName})}catch{$fwList=@()}
$sec=@{antivirus=@{nom=if($avList){$avList[0]}else{$avName};actif=$avActif;temps_reel=$realTime;signature_version=$avSig;signature_age_j=$avAge;a_jour=$avUpToDate;derniere_maj=$avName;editeur='Microsoft'};defender=@{actif=$defActif;version=$defVersion;moteur=$defEngine;platform=$defPlatform;pua=$pua};firewall=@{actif=$fwOk;profils=$fwProfiles;produits=$fwList};bitlocker=@{present=$blCount-gt0;volumes_chiffres=$blProtected;total_volumes=$blCount};secure_boot=$sbActif;credential_guard=$cg;asr=@{actif=$asr;regles=$asrRules};wdac=$wdac;rdp=if(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop|Where-Object{$_.fDenyTSConnections-eq0}){$true}else{$false};smb=if(Get-Service LanmanServer -ErrorAction Stop|Where-Object{$_.Status-eq'Running'}){$true}else{$false}}
if(-not$avActif){$alerts['Aucun antivirus actif']=$true}
if(-not$fwOk){$alerts['Pare-feu desactive']=$true}
Write-Host " AV:$avActif BL:$blCount FW:$fwOk" -ForegroundColor Green

Write-Host "[9/13] Reseau..." -NoNewline
$net=@{}
try{$dnsServers=@(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop|ForEach-Object{$_.ServerAddresses})}catch{$dnsServers=@()}
# Passerelle : Get-NetRoute > WMI/CIM > ipconfig (fr/en)
try{$gw=(Get-NetRoute -DestinationPrefix '0.0.0.0/0'-ErrorAction Stop).NextHop|Select-Object -First1}catch{$gw=''}
if(-not$gw){try{$gw=((Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction Stop|Where-Object{$_.DefaultIPGateway -and $_.IPEnabled}|Select-Object -First1).DefaultIPGateway)|Select-Object -First1}catch{}}
if(-not$gw){try{$gw=((Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop|Where-Object{$_.DefaultIPGateway -and $_.IPEnabled}|Select-Object -First1).DefaultIPGateway)|Select-Object -First1}catch{}}
if(-not$gw){try{$gw=(ipconfig|Select-String -Pattern'(?i)Passerelle.*: (\S+)'|Select-Object -First1).Matches[0].Groups[1].Value}catch{}}
if(-not$gw){try{$gw=(ipconfig|Select-String -Pattern'(?i)Default Gateway.*: (\S+)'|Select-Object -First1).Matches[0].Groups[1].Value}catch{}}
try{$vpn=if(Get-VPNConnection -ErrorAction Stop|Where-Object{$_.ConnectionStatus-eq'Connected'}){$true}else{$false}}catch{$vpn=$false}
try{$proxy=if([System.Net.WebProxy]::GetDefaultProxy().Address){$true}else{$false}}catch{$proxy=$false}
try{$hosts=@();Get-Content "$env:SystemRoot\System32\drivers\etc\hosts"-ErrorAction Stop|Where-Object{$_-notmatch'^#'-and$_-match'^(\d+\.\d+\.\d+\.\d+)\s+(.+)'}|ForEach-Object{$hosts+=$matches[2]}}catch{$hosts=@()}
# Interfaces : Get-NetAdapter (fiable) > WMI fallback
$interfaces=@();try{Get-NetAdapter -ErrorAction Stop|Where-Object{$_.Status-eq'Up'}|ForEach-Object{$ai=$_;$aiIp=Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $ai.ifIndex -ErrorAction Stop|Select-Object -First1;$interfaces+=@{nom=$ai.Name;mac=$ai.MacAddress;ip=if($aiIp){$aiIp.IPAddress}else{''};vitesse_mbps=[Math]::Round($ai.LinkSpeed/1e6,0);status=$ai.Status}}}catch{}
if(-not$interfaces.Count){try{Get-WmiObject Win32_NetworkAdapterConfiguration -ErrorAction Stop|Where-Object{$_.IPEnabled}|ForEach-Object{$interfaces+=@{nom=$_.Description;mac=$_.MACAddress;ip=$_.IPAddress[0];vitesse_mbps=0;status='Up'}}}catch{}}
# Derive MAC/IP/type_reseau depuis l'interface physique principale plutot que $id (parfois faux)
$primMac=$id.mac;$primIp=$id.ip;$primType=$wifi
$physIf=$interfaces|Where-Object{$_.nom -notmatch'(?i)VMware|Virtual|Hyper-V|TAP|OpenVPN|Pseudo|Tunnel|WAN Miniport|Wi-Fi Direct|Bluetooth|Docker|WSL|Loopback'}|Select-Object -First1
if($physIf){$primMac=$physIf.mac;$primIp=$physIf.ip;$primType=if($physIf.nom-match'(?i)Wi-Fi|Wireless|802\.11'){'Wi-Fi'}else{'Ethernet'}}
if(-not$primMac){$primMac=$id.mac};if(-not$primIp){$primIp=$id.ip}
$net=@{ip=$primIp;mac=$primMac;dns=$dnsServers;passerelle=$gw;type_reseau=$primType;vpn=$vpn;proxy=$proxy;interfaces=$interfaces;hosts_entries=$hosts}
Write-Host " $primIp" -ForegroundColor Green

Write-Host "[10/13] Ports+Services..." -NoNewline
$ports=@();$svcs=@()
try{$conns=Get-NetTCPConnection -ErrorAction Stop|Where-Object{$_.State-eq'Listen'}|Select-Object LocalPort,RemotePort,OwningProcess -Unique;foreach($c in $conns){try{$p=Get-Process -Id$c.OwningProcess -ErrorAction Stop;$riskPort='Information';$descPort='';$pt=$c.LocalPort;if($pt-eq3389){$riskPort='Critique';$descPort='RDP - Acces distant'};if($pt-eq445){$riskPort='Critique';$descPort='SMB - Partage fichiers'};if($pt-eq139){$riskPort='Eleve';$descPort='NetBIOS'};if($pt-eq135){$riskPort='Eleve';$descPort='RPC'};if($pt-eq22){$riskPort='Critique';$descPort='SSH'};if($pt-eq23){$riskPort='Critique';$descPort='Telnet'};if($pt-eq21){$riskPort='Critique';$descPort='FTP'};if($pt-eq25){$riskPort='Moyen';$descPort='SMTP'};if($pt-eq80){$riskPort='Faible';$descPort='HTTP'};if($pt-eq443){$riskPort='Faible';$descPort='HTTPS'};if($pt-eq3306){$riskPort='Critique';$descPort='MySQL'};if($pt-eq1433){$riskPort='Critique';$descPort='MSSQL'};if($pt-eq5432){$riskPort='Critique';$descPort='PostgreSQL'};if($pt-eq27017){$riskPort='Critique';$descPort='MongoDB'};if($pt-eq6379){$riskPort='Critique';$descPort='Redis'};if($pt-eq5985-or$pt-eq5986){$riskPort='Critique';$descPort='WinRM'};$ports+=@{port=$pt;risque=$riskPort;description=$descPort;processus=$p.ProcessName;pid=$c.OwningProcess}}catch{}}}catch{}

try{Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object{$_.State-eq'Running'}|ForEach-Object{$svcs+=@{nom=$_.Name;display=$_.DisplayName;path=$_.PathName;demarrage=$_.StartMode;etat=$_.State;pid=$_.ProcessId}}}catch{}
Write-Host " Ports:$($ports.Count) Svcs:$($svcs.Count)" -ForegroundColor Green

Write-Host "[11/13] Processus..." -NoNewline
$procs=@();$suspectProcs=@()
try{Get-Process|Sort-Object WorkingSet -Descending|ForEach-Object{$pp=$_.Path;$susp=$false;$suspR='';if($pp-and$pp-like"$env:TEMP\*"){$susp=$true;$suspR='Execute depuis TEMP'};if($pp-and$pp-like"$env:APPDATA\*"){$susp=$true;$suspR='Execute depuis AppData'};$procs+=@{nom=$_.ProcessName;pid=$_.Id;mem_mb=[Math]::Round($_.WorkingSet/1MB,1);cpu_s=[Math]::Round($_.TotalProcessorTime.TotalSeconds,1);chemin=$pp;description=$_.Description;suspect=$susp;raison_suspecte=$suspR}};foreach($p in $procs){if($p.suspect){$suspectProcs+=$p}}}catch{}
Write-Host " $($procs.Count) (+$($suspectProcs.Count) suspects)" -ForegroundColor Green

Write-Host "[12/13] Persistance..." -NoNewline
$persist=@{}
$run=@();$runOnce=@();$startup=@();$tasks=@();$svcAuto=@();$appInit=@();$bho=@()
try{Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction Stop|Get-Member -MemberType NoteProperty|Where-Object{$_.Name -notmatch'^PS'}|ForEach-Object{$run+=@{nom=$_.Name;valeur=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').$_.Name;provenance='HKLM'}}}catch{}
try{Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -ErrorAction Stop|Get-Member -MemberType NoteProperty|Where-Object{$_.Name -notmatch'^PS'}|ForEach-Object{$run+=@{nom=$_.Name;valeur=(Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run').$_.Name;provenance='HKCU'}}}catch{}
try{Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' -ErrorAction Stop|Get-Member -MemberType NoteProperty|Where-Object{$_.Name -notmatch'^PS'}|ForEach-Object{$runOnce+=@{nom=$_.Name;valeur=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce').$_.Name}}}catch{}
try{Get-ChildItem "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\*"-ErrorAction Stop|ForEach-Object{$startup+=@{nom=$_.Name;chemin=$_.FullName;utilisateur=$env:USERNAME}}}catch{}
try{Get-ChildItem "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\*"-ErrorAction Stop|ForEach-Object{$startup+=@{nom=$_.Name;chemin=$_.FullName;utilisateur='Tous'}}}catch{}
try{Get-ScheduledTask -ErrorAction Stop|Where-Object{$_.State-eq'Ready'}|ForEach-Object{$tasks+=@{nom=$_.TaskName;etat=$_.State;chemin=$_.TaskPath;description=if($_.Description){$_.Description}else{''}}}}catch{}
try{Get-CimInstance Win32_Service -ErrorAction Stop|Where-Object{$_.StartMode-eq'Auto'}|ForEach-Object{$svcAuto+=@{nom=$_.Name;display=$_.DisplayName;chemin=$_.PathName;etat=$_.State}}}catch{}
try{$appInitPath='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows';$dlls=(Get-ItemProperty $appInitPath -Name AppInit_DLLs -ErrorAction Stop).AppInit_DLLs;if($dlls){$loadFor=(Get-ItemProperty $appInitPath -Name LoadAppInit_DLLs -ErrorAction Stop).LoadAppInit_DLLs;$appInit+=@{dlls=$dlls;loadFor=$loadFor}}}catch{}
try{Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects'-ErrorAction Stop|Get-Member -MemberType NoteProperty|Where-Object{$_.Name -notmatch'^PS'}|ForEach-Object{$bho+=@{nom=$_.Name;guid=$_.Name}}}catch{}
$persist=@{run=$run;run_once=$runOnce;startup=$startup;taches_planifiees=$tasks;services_auto=$svcAuto;app_init_dlls=$appInit;browser_helper_objects=$bho}
Write-Host " Run:$($run.Count) Tasks:$($tasks.Count) Svcs:$($svcAuto.Count)" -ForegroundColor Green

Write-Host "[13/13] Mises a jour..." -NoNewline
$updates=@{}
try{$s=New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop;$sr=$s.CreateUpdateSearcher();$cnt=if($sr){$sr.GetTotalHistoryCount()}else{0};if($cnt-gt0){$h=$sr.QueryHistory(0,[Math]::Min($cnt,1));$lastUp=if($h){$h[0].Date.ToString('dd/MM/yyyy')}else{''};$lastUpTitle=if($h){$h[0].Title}else{''}}else{$lastUp='';$lastUpTitle=''};$recent=$sr.QueryHistory(0,[Math]::Min($cnt,20));$upList=@();foreach($u in $recent){$upList+=@{title=$u.Title;date=$u.Date.ToString('dd/MM/yyyy');result=$u.ResultCode}};$updates=@{derniere=$lastUp;derniere_title=$lastUpTitle;total_historique=$cnt;liste=$upList}}catch{$updates=@{derniere='';derniere_title='';total_historique=0;liste=@()}}
Write-Host " $($updates.derniere)" -ForegroundColor Green

# Detection Intune
$intune=@{present=$false;entreprise=@();intune_apps=@();companyportal=$false}
try{$intunePath='HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension';if(Test-Path $intunePath){$intune.present=$true;$apps=@();$win32=Get-ChildItem "$intunePath\Win32Apps"-ErrorAction SilentlyContinue;foreach($a in $win32){try{$an=$a.PSChildName;$apps+=$an}catch{}};$intune.intune_apps=$apps;$intune.entreprise='Intune';if(Get-AppxPackage Microsoft.CompanyPortal -ErrorAction SilentlyContinue){$intune.companyportal=$true}}}catch{}
try{$enroll=Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments'-ErrorAction SilentlyContinue;if($enroll){$intune.present=$true}}catch{}
if($intune.present){Write-Host " Intune detecte" -ForegroundColor Green}

if($eolSw.Count-gt0){$alerts["$($eolSw.Count) logiciel(s) EOL detecte(s)"]=$true}
if($nonAutorises.Count-gt0){$alerts["$($nonAutorises.Count) logiciel(s) non autorise(s)"]=$true}
if($suspectProcs.Count-gt0){$alerts["$($suspectProcs.Count) processus suspect(s)"]=$true}
$elapsed=[Math]::Round(((Get-Date)-$startTime).TotalSeconds,1)

$report=@{version='5.1';date_scan=(Get-Date -Format 'dd/MM/yyyy');heure_scan=(Get-Date -Format 'HH:mm:ss');duree_s=$elapsed;collecteur=@{nom='Collecteur ANSSI v5.1';langage='PowerShell 5.1';admin_requis=$false};identite=$id;systeme=$sys;materiel=$hw;utilisateurs=$users;logiciels=$sw;portables=$pExes;securite=$sec;reseau=$net;ports_ecoute=$ports;services=$svcs;processus=$procs;persistance=$persist;mises_a_jour=$updates;intune=$intune;alertes=@{liste=@($alerts.Keys);count=$alerts.Count}
}

Write-Host "`n================================================" -ForegroundColor Cyan
Write-Host "Machine: $($id.nom) | IP: $($id.ip) | MAC: $($id.mac)" -ForegroundColor Green
Write-Host "Logiciels: $($sw.Count) | EOL: $($eolSw.Count) | Non autorises: $($nonAutorises.Count)" -ForegroundColor Yellow
Write-Host "Processus: $($procs.Count) | Suspects: $($suspectProcs.Count)" -ForegroundColor Yellow
Write-Host "Ports ecoute: $($ports.Count) | Persistance: $($run.Count + $tasks.Count)" -ForegroundColor Yellow
Write-Host "Duree: ${elapsed}s" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan

if($Mode -eq "standalone"){
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jsonPath = Join-Path $OutputDir "inventaire_$($id.nom)_${timestamp}.json"
    try{
        $json = $report | ConvertTo-Json -Depth 8 -Compress
        Set-Content -Path $jsonPath -Value $json -Encoding UTF8
        Write-Host "JSON: $jsonPath" -ForegroundColor Green
    }catch{Write-Host "Export JSON echoue: $($_.Exception.Message)" -ForegroundColor Red}
}

if($Mode -eq "push"){
    Write-Host "Envoi vers $ServerUrl..." -NoNewline
    $ok=$false;$json=$null;$err0='';$err1='';$err2=''
    try{$json=$report|ConvertTo-Json -Depth 8 -Compress}catch{Write-Host "`nJSON conversion ECHEC: $($_.Exception.Message)" -ForegroundColor Red}
    if(-not$json){Write-Host "`nERREUR: ConvertTo-Json a echoue" -ForegroundColor Red}
    # Sauvegarde fichier dans tous les cas
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jsonPath = Join-Path $OutputDir "inventaire_$($id.nom)_${timestamp}.json"
    try{Set-Content -Path $jsonPath -Value $json -Encoding UTF8}catch{}
    # Tentative 1 : simple POST sans compression (timeout 300s)
    if($json){
      try{$wc=New-Object System.Net.WebClient;$wc.Headers.Add('Content-Type','application/json; charset=utf-8');$wc.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();$wc.UploadString("$ServerUrl/api/collecte","POST",$json)|Out-Null;$ok=$true}catch{$err0=$_.Exception.Message}
      if(-not$ok){try{$r=Invoke-WebRequest -Uri "$ServerUrl/api/collecte" -Method POST -Body ([Text.Encoding]::UTF8.GetBytes($json)) -ContentType 'application/json; charset=utf-8' -UseBasicParsing -TimeoutSec 300;if($r.StatusCode-eq200){$ok=$true}else{$err1="HTTP $($r.StatusCode)"}}catch{$err1=$_.Exception.Message}}
    }
    # Tentative 2 : avec Gzip si simple a echoue (timeout 300s)
    if(-not$ok -and $json){
      try{
        $bytes=[System.Text.Encoding]::UTF8.GetBytes($json)
        $ms=New-Object System.IO.MemoryStream
        $gzip=New-Object System.IO.Compression.GzipStream($ms,[System.IO.Compression.CompressionMode]::Compress)
        $gzip.Write($bytes,0,$bytes.Length);$gzip.Close()
        $compressed=$ms.ToArray();$ms.Close()
        $wc=New-Object System.Net.WebClient;$wc.Headers.Add('Content-Type','application/json');$wc.Headers.Add('Content-Encoding','gzip');$wc.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();$wc.UploadData("$ServerUrl/api/collecte","POST",$compressed)|Out-Null;$ok=$true
      }catch{$err2=$_.Exception.Message}
      if(-not$ok){
        try{$r=Invoke-WebRequest -Uri "$ServerUrl/api/collecte" -Method POST -Body $compressed -ContentType 'application/json' -Headers @{'Content-Encoding'='gzip'} -UseBasicParsing -TimeoutSec 300;if($r.StatusCode-eq200){$ok=$true}else{$err2="HTTP $($r.StatusCode)"}}catch{$err2=$_.Exception.Message}
      }
    }
    if($ok){Write-Host " REUSSI" -ForegroundColor Green}else{
      Write-Host " ECHEC" -ForegroundColor Red
      Write-Host "Erreurs:" -ForegroundColor Yellow
      if($err0){Write-Host "  POST simple : $err0" -ForegroundColor Gray}
      if($err1){Write-Host "  POST simpl2: $err1" -ForegroundColor Gray}
      if($err2){Write-Host "  POST gzip  : $err2" -ForegroundColor Gray}
      Write-Host "JSON sauvegarde: $jsonPath" -ForegroundColor Cyan
      Write-Host "Tu peux importer ce fichier depuis le dashboard (Import JSON)" -ForegroundColor Cyan
    }
}

return $report

