# DFIR-Resources

-------------------------------------------------
WinPMEM - an open-source memory acquisition tool.
-------------------------------------------------

Download from https://github.com/Velocidex/WinPmem/releases

Open CMD (run as administrator) and browse to the downloaded directory, and execute the following command as it is a command line tool.

"winpmem_mini_x64_rc2.exe volatilemem.raw"

-----------------------------------------------------------------------------------
Important Windows PowerShell Commands in Forensic Investigation
-----------------------------------------------------------------------------------

Start Windows PowerShell (Run as Administrator)

Lists all the established TCP connections in the system and output to text file:<br>
Get-NetTCPConnection –State Established >>D:\FolderName\FileName.txt

Gets IP route information from the IP routing table and output to text file:<br>
Get-NetRoute >>D:\FolderName\FileName.txt

All the active processes output to text file:<br>
Get-Process >>D:\FolderName\FileName.txt 

Output Windows Event Log (Security Events) to Text Files:<br>
Get-WinEvent -LogName "Security" >>D:\FolderName\FileName.txt

Outputs Startup Program to text File:<br>
Get-CimInstance win32_service -Filter "startmode = 'auto'" >>D:\FolderName\FileName.txt

File Created Time and Modified Time – Export to Text:<br>
Get-ChildItem -Recurse C:\FolderName | Select-Object Mode,CreationTime, LastWriteTime,Length,Name >>D:\FolderName\FileName.txt

Hash entire file content inside a folder using SHA256 and export to text file:<br>
Get-Childitem -path "D:\FolderName" | Get-FileHash >>D:\FolderName\FileName.txt

---------------------------------------------------------------------------------------
Though Chrome-URL list is huge, I have selected few from the list which can be useful for Incident Responders to quickly gather information from Chrome Browser. (Just copy paste the URL)
---------------------------------------------------------------------------------------

chrome://media-engagement <br>
(Displays the media engagement score and thresholds for all sites opened in the browser. The score is used to determine video auto-play with sound)<br>

chrome://indexeddb-internals <br>
(IndexedDB information in the user profile)<br>

chrome://media-internals <br>
(Media information is displayed)<br>

chrome://net-export <br>
(Capture network activity and save it to a file on the disk)<br>

chrome://ntp-tiles-internals <br>
(Displays information about the tiles on the New Tab page and the Top sites functionality)<br>

chrome://predictors <br>
(A list of auto complete and resource prefetch predictors based on past activities)<br>

chrome://signin-internals <br>
(Displays information about the signed in account(s) such as last sign-in details or validity)<br>

chrome://site-engagement <br>
(Display's an engagement score for all sites visited in the browser)<br>

--------------------------------------------------------------------------------------------
Track registry changes (useful for remote collection and analysis as a part of IR Process)
--------------------------------------------------------------------------------------------


In this example, we are tracking changes in "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion"<br>

1) Run PowerShell as admin and take 1st snapshot.<br>
 "dir -rec -erroraction ignore HKLM:\Software\Microsoft\Windows\CurrentVersion | % name > C:\HKLM_Snap_Before.txt"<br>

2) Take 2nd snapshot.<br>
 "dir -rec -erroraction ignore HKLM:\Software\Microsoft\Windows\CurrentVersion | % name > C:\HKLM_Snap_of_Date-$(get-date -f dd-MM-yyyy).txt"<br>

3) Compare 1st and 2nd.<br>
 "Compare-Object (Get-Content -Path C:\HKLM_Snap_Before.txt) (Get-Content -Path [Insert path and file name of 2nd Snapshot (remove square brackets too)])"<br>

Although tools are available, this simple PS script is useful during remote collection and analysis.<br>

---------------------------------------------------------------------------------------------
Windows	Registry	Forensic	Analysis.
---------------------------------------------------------------------------------------------
Time	Zone	Information:<br>
SYSTEM\CurrentControlSet\Control	\TimeZoneInformation<br>

Network	Interfaces	and	Past	Networks:<br>
SYSTEM\CurrentControlSet\Services\Tcpip	\Parameters\Interfaces<br>

Autostart	Programs:<br>
NTUSER.DAT\Software\Microsoft\Windows	\CurrentVersion\Run	<br>
NTUSER.DAT\Software\Microsoft\Windows	\CurrentVersion\RunOnce	<br>
SOFTWARE\Microsoft\Windows\CurrentVersion	\RunOnce	<br>
SOFTWARE\Microsoft\Windows\CurrentVersion	\policies\Explorer\Run	<br>
SOFTWARE\Microsoft\Windows\CurrentVersion\Run<br>

SAM	hive::<br>
SAM\Domains\Account\Users<br>

USB	Device	history:<br>
USB	device	Volume	Name:<br>
SOFTWARE\Microsoft\Windows	Portable	Devices	\Devices<br>

Device	identification (History)<br>
SYSTEM\CurrentControlSet\Enum\USBSTOR<br>
SYSTEM\CurrentControlSet\Enum\USB<br>

First/Last	Times:<br>
SYSTEM\CurrentControlSet\Enum\USBSTOR	\Ven_Prod_Version\USBSerial#\Properties	\{83da6326-
97a6-4088-9453-a19231573b29}\####	<br>
0064=first	connection<br>
0066=last	connection<br>
0067=last	removal<br>

Bluetooth:<br>
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices<br>

File	/	Folder	Usage:<br>
Recent	Files:<br>
NTUSER.DAT\Software\Microsoft\Windows	<br>
\CurrentVersion\Explorer\RecentDocs<br>

Office	Recent	Files:<br>
NTUSER.DAT\Software\Microsoft\Office\VERSION	NTUSER.DAT\Software\Microsoft\Office\VERSION	<br>
\UserMRU\LiveID_####\FileMRU<br>

<b>ShellBags:</b><br>
USRCLASS.DAT\Local	Settings\Software\Microsoft	\Windows\Shell\Bags<br>
USRCLASS.DAT\Local	Settings\Software\Microsoft	\Windows\Shell\BagMRU	<br>
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU	<br>
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags<br>

Open/Save	and	LastVisited	Dialog	MRUs:<br>
NTUSER.DAT\Software\Microsoft\Windows	<br>
\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU	<br>
NTUSER.DAT\Software\Microsoft\Windows	<br>
\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU<br>

Windows	Explorer	Address/Search	Bars:<br>
NTUSER.DAT\Software\Microsoft\Windows	\CurrentVersion\Explorer\TypedPaths	<br>
NTUSER.DAT\Software\Microsoft\Windows	\CurrentVersion\Explorer\WordWheelQuery<br>

Execution:<br>
UserAssist:<br>
NTUSER.DAT\Software\Microsoft\Windows	\Currentversion\Explorer\UserAssist\{GUID}\Count<br>

ShimCache:<br>
SYSTEM\CurrentControlSet\Control\Session	Manager	\AppCompatCache<br><br>

Background	Activity	Moderator	(BAM)	<br>
Desktop Activity	Monitor	(DAM)	(WIN8)<br>
SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}<br>
SYSTEM\CurrentControlSet\Services\dam\UserSettings	\{SID}<br>

--------------------------------------------------------------------------------------------
An important location in Windows to look for deleted records. Windows search index database forensics.
--------------------------------------------------------------------------------------------

Analyse Windows.edb to parse normal records and recover deleted records.<br>

Step 1 : (Stop SearchIndexer in order to copy windows.edb file):<br>
Run PowerShell as Administrator and run this command:<br>
Get-Process | Stop-Process | SearchIndexer<br>

Select [A]<br>

Step 2:<br>
In PowerShell Copy the windows.edb file to an external drive or other location<br>
copy C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb D:\FolderName<br>

Step 3:<br>
Download WinSearchDBAnalyzer by Jeonghyeon Kim (Get link from google)<br>

--------------------------------------------------------------------------------------------
Data Exfiltration Over Bluetooth.
--------------------------------------------------------------------------------------------

History of Bluetooth Registry Entries to investigate (MAC address of connected bluetooth devices) After that use free utility called “Dcode” to convert windows timestamp to check date and time of the bluetooth device that was connected.<br>

“HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices”<br>

--------------------------------------------------------------------------------------------
ETL File Analysis.
--------------------------------------------------------------------------------------------

There are events that carry information about shell Items, network shares, apps that require privileges, RunKey information etc;<br>

When the system boots up, it appears that this file is created and It's location is :<br>

C:\Users\<UserName>\AppData\Local\Microsoft\Windows\Explorer\ExplorerStartupLog.etl.<br>

You can use Tracerpt command-line utility that parses an ETL file's contents and saves them as a CSV or XML file that can be opened in Excel or any text editor.<br>

Open CMD in the folder where ExplorerStartupLog.etl is copied and run this command from there:<br>
“tracerpt ExplorerStartupLog.etl -of CSV”<br>

-------------------------------------------------------------------------------------------

Get hash of all files in a folder and export it to txt file using powershell. Run this command in powershell and remember to change the folder path.
-------------------------------------------------------------------------------------------

You can change -Algorithm MD5 (to any other algorithm).<br>

————

param (
$folders = @("C:\path\folder_name")
)
$allFiles = foreach($folder in $folders) {
Get-Childitem -path $folder -recurse |
select FullName,Name,Length |
foreach {
$hash = Get-FileHash -Algorithm MD5 $_.FullName
add-member -InputObject $_ -NotePropertyName Hash -NotePropertyValue $hash.Hash
add-member -InputObject $_ -NotePropertyName RelativePath -NotePropertyValue $_.FullName.Replace($folder, '') -PassThru
}
}
$allFiles | select -First 10 | ft RelativePath, Hash >> C:\path\folder_name\output_hash.txt<br>

---------------------------------------------------------------------------------------
Active Directory Forensics.
---------------------------------------------------------------------------------------

Ntds.dit file, an Active Directory database that maintains information about user objects, groups, and group membership. It contains the password hashes for all domain users. All data in Active Directory is stored in the file ntds.dit (by default located in C:\Windows\NTDS\) on every domain controller.<br>

ntdsxtract tool (google with this keyword to download the tool)

---------------------------------------------------------------------------------------
Wireshark - most common type of filtering.
---------------------------------------------------------------------------------------

Filter by IP address: displays all traffic from IP, be it source or destination<br>
ip.addr == 192.168.1.1<br>
Filter by source address: display traffic only from IP source<br>
ip.src == 192.168.0.1<br>
Filter by destination: display traffic only form IP destination<br>
ip.dst == 192.168.0.1<br>
Filter by IP subnet: display traffic from subnet, be it source or destination<br>
ip.addr = 192.168.0.1/24<br>
Filter by protocol: filter traffic by protocol name<br>
dns<br>
http<br>
ftp<br>
arp<br>
ssh<br>
telnet<br>
icmp<br>
Exclude IP address: remove traffic from and to IP address<br>
!ip.addr ==192.168.0.1<br>
Display traffic between two specific subnet<br>
ip.addr == 192.168.0.1/24 and ip.addr == 192.168.1.1/24<br>
Display traffic between two specific workstations<br>
ip.addr == 192.168.0.1 and ip.addr == 192.168.0.2<br>
Filter by MAC<br>
eth.addr = 00:50:7f:c5:b6:78<br>
Filter TCP port<br>
tcp.port == 80<br>
Filter TCP port source<br>
tcp.srcport == 80<br>
Filter TCP port destination<br>
tcp.dstport == 80<br>
Find user agents<br>
http.user_agent contains Firefox<br>
!http.user_agent contains || !http.user_agent contains Chrome<br>
Filter broadcast traffic<br>
!(arp or icmp or dns)<br>
Filter IP address and port<br>
tcp.port == 80 && ip.addr == 192.168.0.1<br>
Filter all http get requests<br>
http.request<br>
Filter all http get requests and responses<br>
http.request or http.response<br>
Filter three way handshake<br>
tcp.flags.syn==1 or (tcp.seq==1 and tcp.ack==1 and tcp.len==0 and<br>
tcp.analysis.initial_rtt)<br>
Find files by type<br>
frame contains “(attachment|tar|exe|zip|pdf)”<br>
Find traffic based on keyword<br>
tcp contains facebook<br>
frame contains facebook<br>
Detecting SYN Floods<br>
tcp.flags.syn == 1 and tcp.flags.ack == 0<br>

---------------------------------------------------------------------------------------
Obtain hash of all running executables in Win OS using “CertUtil” while conducting Live Forensics.
---------------------------------------------------------------------------------------

CertUtil in windows is mostly related to managing and viewing certificates, but very useful for getting hash value of any file using -hashfile subcommand.<br>

Here’s the command. Try this out.<br>

FOR /F %i IN ('wmic process where "ExecutablePath is not null" get ExecutablePath') DO certutil -hashfile %i SHA256 | findstr -v : >> output.txt<br>

---------------------------------------------------------------------------------------
Active Directory Ntds.dit Forensics.
---------------------------------------------------------------------------------------

The Ntds.dit file is an Active Directory database that maintains information about user objects, groups, and group membership. It contains the password hashes for all domain users. All data in Active Directory is stored in the file ntds.dit (by default located in C:\Windows\NTDS\) on every domain controller.<br>

ntdsxtract is a framework to provide a solution to extract forensically important information from the main database of Microsoft Active Directory (NTDS.DIT). (Google for ntdsxtract tool)

---------------------------------------------------------------------------------------
SRUM Forensics
---------------------------------------------------------------------------------------

Starting with Microsoft Windows 8, there is a new tool that allows you to track system resource utilisation over time, specifically process and network data. A mechanism called System Resource Usage Monitor (SRUM). It continuously records process-related information such as process owner, CPU cycles spent, data bytes read/written, and network data (sent/received).<br>

The information is stored in the \Windows\System32\sru\ directory in a file named SRUDB.DAT. The file is in the Windows ESE (Extensible Storage Engine) database format.<br>

A forensics tool to convert the data in the Windows srum (System Resource Usage Monitor) database to an xlsx spreadsheet. Download a copy of srum-dump.exe (Google for MarkBaggett/srum-dump)<br>

