#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39340);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/04/23 21:11:57 $");

  script_cve_id("CVE-2009-1138", "CVE-2009-1139");
  script_bugtraq_id(35225, 35226);
  script_osvdb_id(54937, 54938);
  script_xref(name:"MSFT", value:"MS09-018");

  script_name(english:"MS09-018: Vulnerabilities in Active Directory Could Allow Remote Code Execution (971055)");
  script_summary(english:"Checks the file versions of Ntdsa.dll / Adamdsa.dll.");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Active Directory.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Active Directory / Active Directory
Application Mode installed on the remote host is affected by one or
both of the following vulnerabilities :

  - A flaw involving the way memory is freed when handling
    specially crafted LDAP or LDAPS requests allows a
    remote attacker to execute arbitrary code on the remote
    host with administrator privileges. Note that this is
    only known to affect Active Directory on Microsoft
    Windows 2000 Server Service Pack 4. (CVE-2009-1138)

  - Improper memory management during execution of certain
    types of LDAP or LDAPS requests may cause the affected
    product to stop responding. (CVE-2009-1139)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-018");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, Windows XP
and, Windows 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS09-018';
kbs = make_list("969805", "970437");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Determine if ActiveDirectory is enabled.
ADAM_Enabled = FALSE;
NTDS_Enabled = FALSE;

# NTDS check
ntds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Database file");
if (!isnull(ntds_value))
  NTDS_Enabled = TRUE;

# ADAM check
adam_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\ADAM\Performance\Library");
if (!isnull(adam_value))
  ADAM_Enabled = TRUE;

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!NTDS_Enabled && !ADAM_Enabled)
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected since none of the affected Active Directory products are installed.");
}

if (
  # Windows 2003
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdsa.dll",   version:"5.2.3790.4501", dir:"\system32", bulletin:bulletin, kb:"969805")) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.2", sp:2, file:"adamdsa.dll", version:"1.1.3790.4503", dir:"\ADAM", bulletin:bulletin, kb:"970437")) ||

  # Windows XP
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"adamdsa.dll", version:"1.1.3790.4501", dir:"\ADAM", bulletin:bulletin, kb:"970437")) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"adamdsa.dll", version:"1.1.3790.4503", dir:"\ADAM", bulletin:bulletin, kb:"970437")) ||
  (ADAM_Enabled && hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"adamdsa.dll", version:"1.1.3790.4501", dir:"\ADAM", bulletin:bulletin, kb:"970437")) ||

  # Windows 2000
  (NTDS_Enabled && hotfix_is_vulnerable(os:"5.0", file:"ntdsa.dll",   version:"5.0.2195.7292", dir:"\system32", bulletin:bulletin, kb:"969805"))
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
