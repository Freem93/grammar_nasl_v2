#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11818);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_name(english:"MS Blaster Worm (msblast.exe) Infection Detection");
 script_summary(english:"Checks for the presence of msblast.exe");

 script_set_attribute(attribute:"synopsis", value:"The remote host is infected by a virus.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be infected by the MS Blaster worm, or the
Nachi worm, which may make this host attack random hosts on the
internet.");
 script_set_attribute(attribute:"solution", value:
" -
    http://www.symantec.com/security_response/writeup.jsp?do
    cid=2003-081113-0229-99
    -
    http://www.symantec.com/security_response/writeup.jsp?do
    cid=2003-081315-0500-99
    -
    http://www.symantec.com/security_response/writeup.jsp?do
    cid=2003-081312-1554-99
    -
    http://www.symantec.com/security_response/writeup.jsp?do
    cid=2003-082113-3553-99
    -
    http://www.symantec.com/security_response/writeup.jsp?do
    cid=2003-082820-1535-99
    -
    http://www.symantec.com/security_response/writeup.jsp?do
    cid=2003-090105-2513-99
    -
    http://www.symantec.com/security_response/writeup.jsp?do
    cid=2003-081815-2308-99
    -
    http://technet.microsoft.com/en-us/security/bulletin/ms0
    3-039");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/08/11");

script_xref(name:"MSFT", value:"MS03-039");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl","smb_registry_access.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_access");
 script_require_ports(139, 445);
 exit(0);
}

#

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

if(! get_kb_item("SMB/registry_access")) exit(1, "Registry cannot be accessed.");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
 item = "windows auto update";
 array = RegQueryValue(handle:key_h, item:item);
 if(!isnull(array) && ("msblast.exe" >< tolower(array[1]) || "penis32.exe" >< tolower(array[1]) || "mspatch.exe" >< tolower(array[1]) ) )security_hole(port);

 item = "microsoft inet xp..";
 array = RegQueryValue(handle:key_h, item:item);
 if ( ! isnull(array) && "teekids.exe" >< tolower( array[1] ) )
  security_hole(port);

 item = "www.hidro.4t.com";
 array = RegQueryValue(handle:key_h, item:item);
 if ( ! isnull(array) && "enbiei.exe" >< tolower(array[1]) )
  security_hole(port);

 item = "Windows Automation";
 array = RegQueryValue(handle:key_h, item:item);
 if ( ! isnull(array) && "mslaugh.exe" >< tolower(array[1]) )
  security_hole(port);

 RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# Nachi

rootfile = hotfix_get_systemroot();


if ( ! rootfile )  {
	NetUseDel();
	exit(1, "Failed to get system root path.");
	}

NetUseDel(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\wins\dllhost.exe", string:rootfile);


r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}


handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 security_hole(port);
 CloseFile(handle:handle);
}

NetUseDel();

