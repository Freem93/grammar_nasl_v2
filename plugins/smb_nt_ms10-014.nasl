#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(44424);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/11/17 18:50:41 $");

 script_cve_id("CVE-2010-0035");
 script_bugtraq_id(38110);
 script_osvdb_id(62258);
 script_xref(name:"MSFT", value:"MS10-014");

 script_name(english:"MS10-014: Vulnerability in Kerberos Could Allow Denial of Service (977290)");
 script_summary(english:"Checks version of Kdcsvc.dll");

 script_set_attribute(attribute:"synopsis", value:"It is possible to crash the remote service.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Kerberos server that
contains a security flaw that may allow an attacker to crash the
remote service via a NULL pointer dereference.

An attacker would need valid credentials to exploit this
vulnerability.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-014");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, 2003 and
2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-014';
kbs = make_list("977290");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', win2003:'2', vista:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

#Determine if Active Directory is Enabled
ADAM_Enabled = FALSE;
LDS_Enabled = FALSE;
NTDS_Enabled = FALSE;

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SYSTEM\CurrentControlSet\Services\NTDS\Parameters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  NTDS_Enabled = TRUE;
  RegCloseKey(handle:key_h);
}

key = "SYSTEM\CurrentControlSet\Services\DirectoryServices\Performance";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
value = RegQueryValue(handle:key_h, item:"InstallType");
if (!isnull(value))
{
  LDS_Enabled = TRUE;
  RegCloseKey(handle:key_h);
}

key = "SYSTEM\CurrentControlSet\Services\ADAM";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  ADAM_Enabled = TRUE;
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

if (!NTDS_Enabled && !LDS_Enabled && !ADAM_Enabled)
  exit(0, "The host is not affected since none of the affected Active Directory products are installed.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "977290";

if (
  # Win2008
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Kdcsvc.dll", version:"6.0.6001.18374",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Kdcsvc.dll", version:"6.0.6001.22574", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Kdcsvc.dll", version:"6.0.6002.18157",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Kdcsvc.dll", version:"6.0.6002.22280", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Win2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Kdcsvc.dll", version:"5.2.3790.4628",                                dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Win 2000
  hotfix_is_vulnerable(os:"5.0", file:"Kdcsvc.dll", version:"5.0.2195.7361",                                      dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
