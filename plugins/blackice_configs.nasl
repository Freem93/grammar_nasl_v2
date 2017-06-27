#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(14270);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
 script_cve_id("CVE-2004-1714", "CVE-2004-2126");
 script_bugtraq_id(10915);
 script_osvdb_id(8701);

 script_name(english:"ISS BlackICE/PC Protection Unprivileged User Local DoS");
 script_summary(english:"ISS BlackICE Vulnerable config file detection");

 script_set_attribute(attribute:"synopsis", value:
"The firewall running on the remote host has a local buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"ISS BlackICE is a personal Firewall/IDS for windows Desktops. Based on
the version number, the remote BlackICE install is vulnerable to a
local attack due to incorrect file permissions.

*** Nessus based the results of this test on the contents of *** the
local BlackICE configuration file.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Aug/153");
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Aug/494"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Aug/506"
 );
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of BlackICE.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
include("audit.inc");

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(0);
}

key_h = RegOpenKey(key:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\blackd.exe", handle:hklm, mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

item = RegQueryValue(handle:key_h, item:"Default");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(item) ) {
	NetUseDel();
	exit(1);
	}

NetUseDel(close:FALSE);

myfile = str_replace(find:".exe", replace:".log", string:item[1]);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:myfile);
file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:myfile);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1)
{
 NetUseDel();
 exit(1);
}

handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING) ;

if ( isnull(handle) )
{
 NetUseDel();
 exit(1);
}

myread = ReadFile(handle:handle, length:2048, offset:0);
CloseFile(handle:handle);

if ( isnull(myread) )
{
 NetUseDel();
 exit(1);
}

NetUseDel();

myread = str_replace(find:raw_string(0), replace:"", string:myread);

version = egrep(string:myread, pattern:"BlackICE Product Version");
if ( version )
{
	set_kb_item(name:"SMB/BlackICE/Version", value:version);
    	if (ereg(string:version, pattern:"BlackICE Product Version.*3\.([0-5]\.cdf|6\.c(b[drz]|c[a-h]|df))")) security_warning(port);
}
