#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11625);
 script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");
 script_bugtraq_id(7022);
 script_osvdb_id(58904);

 script_name(english:"Dr.Web File Name Handling Overflow");
 script_summary(english:"Determines the presence of Dr.Web");

 script_set_attribute(attribute:"synopsis", value:"The antivirus scanner is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Dr.Web - an antivirus program.

There is a flaw in the remote version of Dr.Web which may make it
crash when scanning files whose name is excessively long.

An attacker may use this flaw to execute arbitrary code on this host.
To exploit it, an attacker would need to send a file to the remote
host and have it scanned by this software.");
 script_set_attribute(attribute:"solution", value:"Upgrade to version 4.29b or newer");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/05/12");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

#

include("smb_func.inc");
include("audit.inc");

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(0);

name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();
#if(!get_port_state(port))exit(0);

#soc = open_sock_tcp(port);

#if ( ! soc ) exit(0);

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


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\DialogueScience\DrWeb", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"Path");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);
if ( isnull(item) ) {
 NetUseDel();
 exit(0);
}

rootfile = item[1];
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if ( ! isnull(version) )
 {
 v = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
 set_kb_item(name:"DrWeb/Version", value:v);
 if ( version[0] < 4 ||
      (version[0] == 4 && version[1] == 0 && version[2] == 0 && version[3] < 29 ) )
 	security_note(port);
 }
}
NetUseDel();
