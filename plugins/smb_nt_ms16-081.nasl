#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91608);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/13 20:59:28 $");

  script_cve_id("CVE-2016-3226");
  script_bugtraq_id(91118);
  script_osvdb_id(139942);
  script_xref(name:"MSFT", value:"MS16-081");
  script_xref(name:"IAVB", value:"2016-B-0101");

  script_name(english:"MS16-081: Security Update for Active Directory (3160352)");
  script_summary(english:"Checks the file versions of Ntdsa.dll / Ntdsai.dll / Adamdsa.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a denial of service vulnerability in Active
Directory. An authenticated, remote attacker can exploit this, via the
creation of multiple machine accounts, to cause the Active Directory
service to stop responding.

Note that an attacker must have access to an account that has
privileges to join machines to the domain in order to exploit this
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-081");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008 R2, 2012, and
2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

bulletin = 'MS16-081';
kb = '3160352';
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# non-server OSes are not affected
if ("Server" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

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

  # Windows 2012 R2
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.3", file:"Ntdsai.dll", version:"6.3.9600.18331", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||

  # Windows 2012
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.2", file:"Ntdsai.dll", version:"6.2.9200.21856", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb)
    )
  ) ||

  # Windows 2008 R2
  (
    (NTDS_Enabled || LDS_Enabled) &&
    (
      hotfix_is_vulnerable(os:"6.1", file:"Ntdsai.dll", version:"6.1.7601.23445", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb)
    )
  )
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
