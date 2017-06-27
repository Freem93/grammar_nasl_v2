#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(11363);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

 script_cve_id("CVE-2003-1393");
 script_bugtraq_id(6808);
 script_osvdb_id(59067);
 script_xref(name:"Secunia", value:"8023");

 script_name(english:"Gupta SQLBase EXECUTE Command Remote Overflow");
 script_summary(english:"Determines the version of the remote Gupta SQLBase server");

 script_set_attribute(attribute:"synopsis", value:"The remote SQL server is affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Gupta SQLBase server which
is older than or equal to 8.1.0.

An error in the 'Execute' command makes it possible to trigger a
buffer overflow by supplying more than 700 characters as the
parameter. A remote, authenticated attacker, exploiting this flaw, can
crash the affected service or potentially execute arbitrary code with
SYSTEM privileges.");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/12");

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

if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);


name 	= kb_smb_name();
login	= kb_smb_login();
pass  	= kb_smb_password();
domain 	= kb_smb_domain();
port    = kb_smb_transport();
#if(!get_port_state(port))exit(1);

#soc = open_sock_tcp(port);
#if(!soc)exit(1);

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


key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Services\Gupta SQLBase", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(1);
}


item = RegQueryValue(handle:key_h, item:"ImagePath");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(item) )
{
 NetUseDel();
 exit(1);
}

NetUseDel(close:FALSE);
rootfile = item[1];
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
 NetUseDel();
 exit(1);
}


handle = CreateFile (file:file, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL,
                     share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);
if( ! isnull(handle) )
{
 version = GetFileVersion(handle:handle);
 CloseFile(handle:handle);

 if ( !isnull(version) )
 {
  if ( version[0] < 8 ||
     (version[0] == 8  && version[1] == 0 ) ||
     (version[0] == 8  && version[1] == 1 && version[2] == 0 && version[3] == 0 ) )
    security_hole(port);
 }
}


NetUseDel();
