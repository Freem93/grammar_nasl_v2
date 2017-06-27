#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(22131);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");

 script_cve_id("CVE-2006-3992");
 script_bugtraq_id(19298, 19864);
 script_osvdb_id(29315);
 script_name(english:"Intel PRO/Wireless Network Connection Drivers Remote Code Execution Vulnerabilities");
 script_summary(english:"Determines the version of the Intel Wireless/PRO driver");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Intel Wireless/PRO 2200/2915
driver that is is affected by a memory corruption vulnerability. An
attacker may exploit this flaw to execute arbitrary code on the remote
host with kernel privileges or to disable the remote service remotely.

To exploit this flaw, an attacker would need to send a specially
crafted wireless frame to the remote host.");
 script_set_attribute(attribute:"solution", value:"http://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00001");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/02");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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

key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Services\w22n51", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 key_h = RegOpenKey(handle:hklm, key:"SYSTEM\CurrentControlSet\Services\w29n51", mode:MAXIMUM_ALLOWED);
 if ( isnull(key_h) )
 {
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
 }
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
 if ( ( v[0] < 9 ) ||
      ( ( v[0] == 9 ) && ( v[1] == 0 ) && ( v[2] < 4 ) ) ||
      ( ( v[0] == 9 ) && ( v[1] == 0 ) && ( v[2] == 4 ) && ( v[3] < 16 ) ) )
    security_hole(port);
}

NetUseDel();
