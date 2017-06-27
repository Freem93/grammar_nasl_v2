#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57281);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-3406");
  script_bugtraq_id(50959);
  script_osvdb_id(77667);
  script_xref(name:"MSFT", value:"MS11-095");

  script_name(english:"MS11-095: Vulnerability in Active Directory Could Allow Remote Code Execution (2640045)");
  script_summary(english:"Checks the file versions of Ntdsa.dll / Ntdsai.dll / Adamdsa.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The installed version of Active Directory is affected by a
vulnerability that allows code execution.");
  script_set_attribute(attribute:"description", value:
"The version of Active Directory installed on the remote host is is
affected by a buffer overflow vulnerability. A remote, authenticated
attacker can exploit this flaw to execute arbitrary code on the remote
host subject to the privileges of the user running the Active
Directory service.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-095");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS11-095';
kbs = make_list('2621146', '2626416');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

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
      hotfix_is_vulnerable(os:"6.1", file:"Ntdsai.dll", version:"6.1.7601.21841", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2621146") ||
      hotfix_is_vulnerable(os:"6.1", file:"Ntdsai.dll", version:"6.1.7601.17709", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:"2621146") ||
      hotfix_is_vulnerable(os:"6.1", file:"Ntdsai.dll", version:"6.1.7600.21071", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2621146") ||
      hotfix_is_vulnerable(os:"6.1", file:"Ntdsai.dll", version:"6.1.7600.16900", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2621146")
    )
  ) ||

  # Vista / Windows Server 2008
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsai.dll",   version:"6.0.6002.22731", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"2621146") ||
      hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsai.dll",   version:"6.0.6002.18532", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2621146")
    )
  ) ||

  # Windows 2003
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdsa.dll",   version:"5.2.3790.4929", dir:"\system32", bulletin:bulletin, kb:"2621146")) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.4921", dir:"\ADAM",     bulletin:bulletin, kb:"2626416")) ||

  # Windows XP
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:3, file:"adamdsa.dll", version:"1.1.3790.4921", dir:"\ADAM",     bulletin:bulletin, kb:"2626416"))
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
