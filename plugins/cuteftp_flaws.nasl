#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
 script_id(11756);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2003-1260", "CVE-2003-1261");
 script_bugtraq_id(6642, 6786);
 script_osvdb_id(2181, 58838);

 script_name(english:"CuteFTP < 5.0.2.0 Multiple Vulnerabilities");
 script_summary(english:"Determines the presence of CuteFTP.exe");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP client is affected by various issues.");
 script_set_attribute(attribute:"description", value:
"CuteFTP, an FTP client, is installed on the remote Windows host.

The version of CuteFTP on the remote host reportedly is affected by a
buffer overflow that may be exploited by an attacker to execute
arbitrary commands, subject to the privileges of the current user. To
exploit this issue, an attacker would need to set up a rogue FTP
server and lure a user of this host to browse it using CuteFTP.

In addition, the client is also affected by a flaw in which a local
user can crash the client by copying a long URL into the clipboard.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jan/125");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Feb/89" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jun/154" );
 script_set_attribute(attribute:"solution", value:"Upgrade to CuteFTP 5.0.2.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/01/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/18");

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}


key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\GlobalScape Inc.\CuteFTP", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}

value = RegQueryValue(handle:key_h, item:"CmdLine");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(1);
}

rootfile = value[1];
NetUseDel(close:FALSE);


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

 if ( !isnull(version) )
 {
 v = string(version[0], ".", version[1], ".", version[2], ".", version[3]);
 if ( version[0] < 5 || (version[0] == 5 && version[1] == 0 && version[2] <= 1 ) ) security_hole(port);
 }
}


NetUseDel();
