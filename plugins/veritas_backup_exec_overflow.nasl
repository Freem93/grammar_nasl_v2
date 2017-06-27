#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16230);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/11/29 20:13:36 $");

 script_cve_id("CVE-2004-1172");
 script_bugtraq_id(11974);
 script_osvdb_id(12418);
 script_xref(name:"EDB-ID", value:"750");
 script_xref(name:"CERT", value:"907729");

 script_name(english:"Veritas Backup Exec Agent Browser 8.x < 8.60.3878 HF 68 / 9.0.x < 9.0.4454 HF 30 / 9.1.x < 9.1.4691 HF 40 RCE");
 script_summary(english:"Determines the version of VERITAS Backup Exec Agent Browser.");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The version of Veritas Backup Exec Agent Browser installed on the
remote host is 8.x prior to 8.60.3878 hotfix 68, 9.0.x prior to
9.0.4454 hotfix 30, or 9.1.x prior to 9.1.4691 hotfix 40. It is,
therefore, affected by a remote code execution vulnerability in the
registration service (benetns.exe) due to a failure to validate the
client hostname field during the registration process. An
unauthenticated, remote attacker can exploit this, via a specially
crafted request, to cause a stack-based buffer overflow, resulting in
the execution of arbitrary code.");
 # https://web.archive.org/web/20100323040855/http://seer.support.veritas.com/docs/273419.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?191bec81");
 # https://web.archive.org/web/20050205165626/http://seer.support.veritas.com/docs/273420.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7aa777ec");
 # https://web.archive.org/web/20050205131442/http://seer.support.veritas.com/docs/273422.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0e640a0");
 # https://web.archive.org/web/20060619215201/http://seer.support.veritas.com/docs/273850.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03ad9b52");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas Backup Exec Agent Browser 8.60.3878 hotfix 68 /
9.0.4454 hotfix 30 / 9.1.4691 hotfix 40 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Veritas Backup Exec Name Service Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/16");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec_veritas:backup_exec");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("smb_func.inc");
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

key_h = RegOpenKey(handle:hklm, key:"SOFTWARE\VERITAS\Backup Exec\Install", mode:MAXIMUM_ALLOWED);
if ( isnull(key_h) )
{
 RegCloseKey(handle:hklm);
 NetUseDel();
 exit(0);
}

value = RegQueryValue(handle:key_h, item:"Path");
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
if ( isnull(value) )
{
 NetUseDel();
 exit(0);
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:value[1]);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\benetns.exe", string:value[1]);
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
 if ( ( v[0] < 8 ) ||
      ( ( v[0] == 8 ) && ( v[1] < 60 ) ) ||
      ( ( v[0] == 8 ) && ( v[1] == 60 ) && ( v[2] < 3878 ) ) ||
      ( ( v[0] == 8 ) && ( v[1] == 60 ) && ( v[2] == 3878 ) && ( v[3] < 68 ) ) ||
      ( ( v[0] == 9 ) && ( v[1] == 0 ) && ( v[2] < 4454 ) ) ||
      ( ( v[0] == 9 ) && ( v[1] == 0 ) && ( v[2] == 4454 ) && ( v[3] < 30 ) ) ||
      ( ( v[0] == 9 ) && ( v[1] == 1 ) && ( v[2] < 4691 ) ) ||
      ( ( v[0] == 9 ) && ( v[1] == 1 ) && ( v[2] == 4691 ) && ( v[3] < 40 ) ) )
    security_hole(port);
}

NetUseDel();
