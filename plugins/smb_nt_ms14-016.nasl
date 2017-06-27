#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72935);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/13 04:38:20 $");

  script_cve_id("CVE-2014-0317");
  script_bugtraq_id(66012);
  script_osvdb_id(104313);
  script_xref(name:"MSFT", value:"MS14-016");

  script_name(english:"MS14-016: Vulnerability in Security Account Manager Remote (SAMR) Protocol Could Allow Security Feature Bypass (2934418)");
  script_summary(english:"Checks versions of samsrv.dll / adamdsa.dll / ntdsa.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A security feature bypass vulnerability exists in Windows due to the
Security Account Manager Remote (SAMR) protocol incorrectly validating
the user lockout state. Remote, authenticated attackers can exploit
this issue to conduct brute force attacks against user passwords.

Note that the host must have network connectivity to a domain
controller.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-016");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, XP, Vista,
2008, 2008 R2, 2012, 2012 R2, and Server Core installation option.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS14-016';
kb = '2934418';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 7" >< productname || "Windows 8" >< productname || "Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

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

if (
  # Windows Server 2012 R2
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.3", sp:0, file:"samsrv.dll",   version:"6.3.9600.16506", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||

  # Windows Server 2012
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.2", sp:0, file:"samsrv.dll",   version:"6.2.9200.20910", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.2", sp:0, file:"samsrv.dll",   version:"6.2.9200.16791", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||

  # Windows Server 2008 R2
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"samsrv.dll",   version:"6.1.7601.22579", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:"samsrv.dll",   version:"6.1.7601.18377", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||

  # Vista / Windows Server 2008
  (NTDS_Enabled && hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdsai.dll", version:"6.0.6002.23317", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb)) ||
  (NTDS_Enabled && hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdsai.dll", version:"6.0.6002.19029", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb)) ||
  (LDS_Enabled && hotfix_is_vulnerable(os:"6.0", sp:2, file:"samsrv.dll",   version:"6.0.6002.23317", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb)) ||
  (LDS_Enabled && hotfix_is_vulnerable(os:"6.0", sp:2, file:"samsrv.dll",   version:"6.0.6002.19029", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb)) ||

  # Windows 2003 and XP x64
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdsatq.dll",   version:"1.1.3790.5297", dir:"\system32", bulletin:bulletin, kb:kb)) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.5297", dir:"\ADAM", bulletin:bulletin, kb:"2933528")) ||

  # Windows XP x86
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:3, file:"adamdsa.dll", version:"1.1.3790.5289", dir:"\ADAM", bulletin:bulletin, kb:"2933528"))
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
