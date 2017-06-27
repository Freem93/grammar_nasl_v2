#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99306);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id("CVE-2017-0166");
  script_bugtraq_id(97446);
  script_osvdb_id(155346);
  script_xref(name:"MSKB", value:"4015068");

  script_name(english:"KB4015068: Security Update for the LDAP Elevation of Privilege Vulnerability (April 2017)");
  script_summary(english:"Checks the version of ntdsai.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing security update KB4015068. It is,
therefore, affected by a flaw in LDAP due to buffer request lengths
not being properly calculated. An unauthenticated, remote attacker can
exploit this, via specially crafted traffic sent to a Domain
Controller, to run processes with elevated privileges.");
  # https://support.microsoft.com/en-us/help/4015068/security-update-for-the-ldap-elevation-of-privilege-vulnerability
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cf789b2");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0166
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25c40acd");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4015068.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS17-04';
kbs = make_list("4015068");
vuln = 0;

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Determine if Active Directory is enabled.
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

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (
  (NTDS_Enabled || LDS_Enabled) &&
  (
  # Windows Vista Service Pack 2 / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdsai.dll", version:"6.0.6002.19749", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4015068") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdsai.dll", version:"6.0.6002.24072", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"4015068")
  )
)
  vuln++;

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
