#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49226);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2010-0820");
  script_bugtraq_id(43037);
  script_osvdb_id(67987);
  script_xref(name:"MSFT", value:"MS10-068");

  script_name(english:"MS10-068: Vulnerability in Local Security Authority Subsystem Service Could Allow Elevation of Privilege (983539)");
  script_summary(english:"Checks the file versions of Ntdsa.dll / Ntdsai.dll / Adamdsa.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Active Directory on the remote Windows host can be used
to execute arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The version of the Local Security Authority Subsystem Service (LSASS)
installed on the remote Windows host does not properly handle
malformed packets in LDAP messages when used in conjunction with
Microsoft Active Directory / Active Directory Application Mode /
Active Directory Lightweight Directory Service.

By sending a specially crafted LDAP message to a listening LSASS
server, an authenticated attacker with a member account within the
target Windows domain can overflow a buffer and execute arbitrary
code, thereby gaining complete control of the affected system.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-068");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-068';
kbs = make_list("981550", "982000");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Determine if Active Directory is enabled.
ADAM_Enabled = FALSE;
LDS_Enabled  = FALSE;
NTDS_Enabled = FALSE;

# NTDS check
ntds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Database file");
if (!isnull(ntds_value))
  NTDS_Enabled = TRUE;

# LDS check
lds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\DirectoryServices\Performance\InstallType");
if (!isnull(lds_value))
  LDS_Enabled = TRUE;

# ADAM check
adam_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\ADAM\Performance\Library");
if (!isnull(adam_value))
  ADAM_Enabled = TRUE;

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!NTDS_Enabled && !LDS_Enabled && !ADAM_Enabled)
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected since none of the affected Active Directory products are installed.");
}

# Check the file version.
if (
  # Windows 7 / Server 2008 R2
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.1", sp:0, file:"Ntdsai.dll",   version:"6.1.7600.20735", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:'981550') ||
      hotfix_is_vulnerable(os:"6.1", sp:0, file:"Ntdsai.dll",   version:"6.1.7600.16612", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'981550')
    )
  ) ||

  # Vista / Windows Server 2008
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsai.dll",   version:"6.0.6002.22384", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:'981550') ||
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsai.dll",   version:"6.0.6002.18244", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'981550') ||
      hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntdsai.dll",   version:"6.0.6001.22672", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:'981550') ||
      hotfix_is_vulnerable(os:"6.0", sp:1, file:"Ntdsai.dll",   version:"6.0.6001.18461",                               dir:"\system32", bulletin:bulletin, kb:'981550')
    )
  ) ||

  # Windows 2003
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdsa.dll",   version:"5.2.3790.4754", dir:"\system32", bulletin:bulletin, kb:'981550')) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.4722", dir:"\ADAM", bulletin:bulletin, kb:'982000')) ||

  # Windows XP
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:3, file:"adamdsa.dll", version:"1.1.3790.4722", dir:"\ADAM", bulletin:bulletin, kb:'982000'))
)
{
  set_kb_item(name:"SMB/Missing/MS10-068", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
