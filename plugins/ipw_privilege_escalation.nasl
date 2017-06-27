#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(22132);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

 script_cve_id("CVE-2006-4022");
 script_bugtraq_id(19299);
 script_osvdb_id(29314);
 script_name(english:"Intel PRO/Wireless 2100 Network Connection Driver Local Privilege Escalation Vulnerability");
 script_summary(english:"Determines the version of Intel Wireless/PRO 2100 driver");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Intel Wireless/PRO 2100 driver
that is fails to properly handle certain malformed frames. A local
attacker may exploit this flaw to elevate his privileges (SYSTEM) on
the remote host.

To exploit this flaw, an attacker would need to send a specially
crafted wireless frame to the Intel driver.");
 script_set_attribute(attribute:"solution", value:"http://www.nessus.org/u?58136174");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/02");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if ( ! get_kb_item("SMB/Registry/Enumerated") ) exit(1);


name 	=  kb_smb_name();
login	=  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 exit(1);
}

key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Services\w70n51", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"ImagePath");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(0);
}

value = hotfix_get_systemroot() + "\" + value[1];
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:value);
NetUseDel(close:FALSE);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) {
 NetUseDel();
 exit(1);
}



handle = CreateFile (file:exe, desired_access:GENERIC_READ, file_attributes:FILE_ATTRIBUTE_NORMAL, share_mode:FILE_SHARE_READ, create_disposition:OPEN_EXISTING);


if ( ! isnull(handle) )
{
 v = GetFileVersion(handle:handle);
 CloseFile(handle:handle);
 if (!isnull(v))
 if ( ( v[0] < 1 ) ||
      ( ( v[0] == 1 ) && ( v[1] < 2 ) ) ||
      ( ( v[0] == 1 ) && ( v[1] == 2 ) && ( v[2] < 4 ) ) ||
      ( ( v[0] == 1 ) && ( v[1] == 2 ) && ( v[2] == 4 ) && ( v[3] < 37 ) ) )
    security_warning(port);
}

NetUseDel();
