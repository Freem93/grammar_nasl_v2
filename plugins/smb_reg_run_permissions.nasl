#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10430);
 script_version("$Revision: 1.35 $");
 script_cvs_date("$Date: 2015/12/04 17:38:20 $");
 script_cve_id("CVE-1999-0589");
 script_osvdb_id(331, 332, 334);

 script_name(english:"Microsoft Windows SMB Registry : Key Permission Weakness Admin Privilege Escalation");
 script_summary(english:"Determines the access rights of a remote key");

 script_set_attribute(attribute:"synopsis", value:"Local users can gain administrator privileges.");
 script_set_attribute(attribute:"description", value:
"The following keys contain the name of the program that shall be
started when the computer starts. The users who have the right to
modify them can easily make the admin run a Trojan program that will
give them admin privileges.");
 script_set_attribute(attribute:"solution", value:
"Use regedt32 and set the permissions of this key to :

  - Admin group  : Full Control
  - System       : Full Control
  - Everyone     : Read

Make sure that 'Power Users' do not have any special privilege for
this key.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/10/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/29");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_access.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

access = get_kb_item_or_exit("SMB/registry_access");

port = get_kb_item("SMB/transport");
if (!port)port = 139;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

name	= kb_smb_name(); 	if(!name)exit(0);
login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:name);
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# HKLM keys
keys[0  ] = "System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms";
keys[1  ] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AppSetup";
keys[2  ] = "Software\Policies\Microsoft\Windows\System\Scripts\Startup";
keys[3  ] = "Software\Policies\Microsoft\Windows\System\Scripts\Logon";
keys[4  ] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit";
keys[5  ] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\VmApplet";
keys[6  ] = "Software\Policies\Microsoft\Windows\System\Scripts\Shutdown";
keys[7  ] = "Software\Policies\Microsoft\Windows\System\Scripts\Logoff";
keys[8  ] = "Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup";
keys[9  ] = "Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown";
keys[10 ] = "Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell";
keys[11 ] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell";
keys[12 ] = "SYSTEM\CurrentControlSet\Control\SafeBoot\AlternateShell";
keys[13 ] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman";
keys[14 ] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce";
keys[15 ] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run";
keys[16 ] = "SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram";
keys[17 ] = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
keys[18 ] = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run";
keys[19 ] = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
keys[20 ] = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce";
keys[21 ] = "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run";
keys[22 ] = "SOFTWARE\Microsoft\Active Setup\Installed Components";
keys[23 ] = "Software\Microsoft\Windows NT\CurrentVersion\Windows\IconServiceLib";
keys[24 ] = "SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components";
keys[25 ] = "SOFTWARE\Microsoft\Windows CE Services\AutoStartOnConnect";
keys[26 ] = "SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnConnect";
keys[27 ] = "SOFTWARE\Microsoft\Windows CE Services\AutoStartOnDisconnect";
keys[28 ] = "SOFTWARE\Wow6432Node\Microsoft\Windows CE Services\AutoStartOnDisconnect";
keys[29 ] = "SOFTWARE\Classes\Protocols\Filter";
keys[30 ] = "SOFTWARE\Classes\Protocols\Handler";
keys[31 ] = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler";
keys[32 ] = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler";
keys[33 ] = "SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad";
keys[34 ] = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad";
keys[35 ] = "Software\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks";
keys[36 ] = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks";
keys[37 ] = "Software\Classes\*\ShellEx\ContextMenuHandlers";
keys[38 ] = "Software\Wow6432Node\Classes\*\ShellEx\ContextMenuHandlers";
keys[39 ] = "Software\Classes\*\ShellEx\PropertySheetHandlers";
keys[40 ] = "Software\Wow6432Node\Classes\*\ShellEx\PropertySheetHandlers";
keys[41 ] = "Software\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers";
keys[42 ] = "Software\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers";
keys[43 ] = "Software\Classes\AllFileSystemObjects\ShellEx\DragDropHandlers";
keys[44 ] = "Software\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\DragDropHandlers";
keys[45 ] = "Software\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers";
keys[46 ] = "Software\Wow6432Node\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers";
keys[47 ] = "Software\Classes\Directory\ShellEx\ContextMenuHandlers";
keys[48 ] = "Software\Wow6432Node\Classes\Directory\ShellEx\ContextMenuHandlers";
keys[49 ] = "Software\Classes\Directory\Shellex\DragDropHandlers";
keys[50 ] = "Software\Wow6432Node\Classes\Directory\Shellex\DragDropHandlers";
keys[51 ] = "Software\Classes\Directory\Shellex\PropertySheetHandlers";
keys[52 ] = "Software\Wow6432Node\Classes\Directory\Shellex\PropertySheetHandlers";
keys[53 ] = "Software\Classes\Directory\Shellex\CopyHookHandlers";
keys[54 ] = "Software\Wow6432Node\Classes\Directory\Shellex\CopyHookHandlers";
keys[55 ] = "Software\Classes\Directory\Background\ShellEx\ContextMenuHandlers";
keys[56 ] = "Software\Wow6432Node\Classes\Directory\Background\ShellEx\ContextMenuHandlers";
keys[57 ] = "Software\Classes\Folder\Shellex\ColumnHandlers";
keys[58 ] = "Software\Wow6432Node\Classes\Folder\Shellex\ColumnHandlers";
keys[59 ] = "Software\Classes\Folder\ShellEx\ContextMenuHandlers";
keys[60 ] = "Software\Wow6432Node\Classes\Folder\ShellEx\ContextMenuHandlers";
keys[61 ] = "Software\Classes\Folder\ShellEx\DragDropHandlers";
keys[62 ] = "Software\Wow6432Node\Classes\Folder\ShellEx\DragDropHandlers";
keys[63 ] = "Software\Classes\Folder\ShellEx\ExtShellFolderViews";
keys[64 ] = "Software\Wow6432Node\Classes\Folder\ShellEx\ExtShellFolderViews";
keys[65 ] = "Software\Classes\Folder\ShellEx\PropertySheetHandlers";
keys[66 ] = "Software\Wow6432Node\Classes\Folder\ShellEx\PropertySheetHandlers";
keys[67 ] = "Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers";
keys[68 ] = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers";
keys[69 ] = "Software\Microsoft\Ctf\LangBarAddin";
keys[70 ] = "Software\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";
keys[71 ] = "Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects";
keys[72 ] = "Software\Microsoft\Internet Explorer\Toolbar";
keys[73 ] = "Software\Wow6432Node\Microsoft\Internet Explorer\Toolbar";
keys[74 ] = "Software\Microsoft\Internet Explorer\Explorer Bars";
keys[75 ] = "Software\Wow6432Node\Microsoft\Internet Explorer\Explorer Bars";
keys[76 ] = "Software\Microsoft\Internet Explorer\Extensions";
keys[77 ] = "Software\Wow6432Node\Microsoft\Internet Explorer\Extensions";
keys[78 ] = "System\CurrentControlSet\Services";
keys[79 ] = "System\CurrentControlSet\Services";
keys[80 ] = "Software\Microsoft\Windows NT\CurrentVersion\Drivers32";
keys[81 ] = "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32";
keys[82 ] = "Software\Classes\Filter";
keys[83 ] = "Software\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance";
keys[84 ] = "Software\Wow6432Node\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance";
keys[85 ] = "Software\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance";
keys[86 ] = "Software\Wow6432Node\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance";
keys[87 ] = "Software\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance";
keys[88 ] = "Software\Wow6432Node\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance";
keys[89 ] = "Software\Classes\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance";
keys[90 ] = "Software\Wow6432Node\Classes\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance";
keys[91 ] = "System\CurrentControlSet\Control\Session Manager\BootExecute";
keys[92 ] = "System\CurrentControlSet\Control\Session Manager\SetupExecute";
keys[93 ] = "System\CurrentControlSet\Control\Session Manager\Execute";
keys[94 ] = "System\CurrentControlSet\Control\Session Manager\S0InitialCommand";
keys[95 ] = "System\CurrentControlSet\Control\ServiceControlManagerExtension";
keys[96 ] = "Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
keys[97 ] = "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
keys[98 ] = "Software\Microsoft\Command Processor\Autorun";
keys[99 ] = "Software\Wow6432Node\Microsoft\Command Processor\Autorun";
keys[100] = "SOFTWARE\Classes\Exefile\Shell\Open\Command\(Default)";
keys[101] = "Software\Classes\.exe";
keys[102] = "Software\Classes\.cmd";
keys[103] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls";
keys[104] = "SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls";
keys[105] = "System\CurrentControlSet\Control\Session Manager\AppCertDlls";
keys[106] = "System\CurrentControlSet\Control\Session Manager\KnownDlls";
keys[107] = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers";
keys[108] = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters";
keys[109] = "SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers";
keys[110] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\System";
keys[111] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify";
keys[112] = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SaveDumpStart";
keys[113] = "System\CurrentControlSet\Control\BootVerificationProgram\ImagePath";
keys[114] = "System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries";
keys[115] = "System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries";
keys[116] = "System\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64";
keys[117] = "System\CurrentControlSet\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64";
keys[118] = "SYSTEM\CurrentControlSet\Control\Print\Monitors";
keys[119] = "SYSTEM\CurrentControlSet\Control\SecurityProviders\SecurityProviders";
keys[120] = "SYSTEM\CurrentControlSet\Control\Lsa\Authentication Packages";
keys[121] = "SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages";
keys[122] = "SYSTEM\CurrentControlSet\Control\Lsa\Security Packages";
keys[123] = "SYSTEM\CurrentControlSet\Control\NetworkProvider\Order";

vuln = 0;
vuln_keys = "";

for(my_counter=0;keys[my_counter];my_counter=my_counter+1)
{
 key_h = RegOpenKey(handle:hklm, key:keys[my_counter], mode:MAXIMUM_ALLOWED | ACCESS_SYSTEM_SECURITY);

 if(!isnull(key_h))
 {
  rep = RegGetKeySecurity (handle:key_h, type: DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION);
  if(!isnull(rep) && registry_key_writeable_by_non_admin(security_descriptor:rep))
  {
   vuln_keys += '\nHKLM\\' + keys[my_counter];
   vuln = vuln + 1;
  }
  RegCloseKey (handle:key_h);
 }
}

RegCloseKey (handle:hklm);
NetUseDel();

if(vuln)
{
 report =
"The following registry keys are writeable by users who are not in
the admin group :
"
+
 vuln_keys ;

 security_hole(port:port, extra:report);
}
else audit(AUDIT_HOST_NOT, 'affected');
