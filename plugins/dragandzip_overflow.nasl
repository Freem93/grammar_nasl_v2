#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11631);
 script_version("$Revision: 1.12 $");
 script_osvdb_id(58903);
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_name(english:"Drag And Zip File Name Handling Overflow");
 script_summary(english:"Determines the presence of Drag And Zip");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Drag And Zip - a file compression utility.

There is a flaw in this program which may allow a remote attacker to
execute arbitrary code on this host.

To exploit this flaw, an attacker would need to craft a special Zip
file and send it to a user on this host. Then, the user would need to
open it using Drag And Zip.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/May/118");
 script_set_attribute(attribute:"solution", value:"None");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);

include("smb_func.inc");
include("audit.inc");


name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
if(!port) port = 139;


#if(!get_port_state(port))exit(0);

#soc = open_sock_tcp(port);
#if(!soc)exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\Canyon\InstalledApps\DragAndZip", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"Install Directory");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if ( isnull(value) ) {
	NetUseDel();
	exit(0);
}

rootfile = value[1];
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Dz32.exe", string:rootfile);


r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(0);
}

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 security_warning(port);
 CloseFile(handle:handle);
}

NetUseDel();
