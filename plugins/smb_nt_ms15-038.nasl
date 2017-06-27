#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82774);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-1643", "CVE-2015-1644");
  script_bugtraq_id(73998, 74014);
  script_osvdb_id(120634, 120635);
  script_xref(name:"MSFT", value:"MS15-038");
  script_xref(name:"IAVA", value:"2015-A-0091");

  script_name(english:"MS15-038: Vulnerabilities in Microsoft Windows Could Allow Elevation of Privilege (3049576)");
  script_summary(english:"Checks the version of clfs.sys and ntdll.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple privilege escalation
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple privilege escalation vulnerabilities :

  - A elevation of privilege vulnerability exists due to
    NtCreateTransactionManager type confusion that allows
    an authenticated attacker to bypass impersonation-level
    security checks by running a specially crafted
    application. (CVE-2015-1643)

  - A elevation of privilege vulnerability exists due to a
    MS-DOS device name handling flaw that allows an
    authenticated attacker to bypass impersonation-level
    security checks by running a specially crafted
    application. (CVE-2015-1644)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-038");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-038';

kbs = make_list("3045685","3045999");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# The 2k3 checks could flag XP 64, which is unsupported
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"clfs.sys", version:"6.3.9600.17719", min_version:"6.3.9600.16000", dir:"\drivers", bulletin:bulletin, kb:"3045685") ||
  hotfix_is_vulnerable(os:"6.3", file:"ntdll.dll", version:"6.3.9600.17736", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3045999") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"clfs.sys", version:"6.2.9200.21408", min_version:"6.2.9200.20000", dir:"\drivers", bulletin:bulletin, kb:"3045685") ||
  hotfix_is_vulnerable(os:"6.2", file:"clfs.sys", version:"6.2.9200.17291", min_version:"6.2.9200.16000", dir:"\drivers", bulletin:bulletin, kb:"3045685") ||
  hotfix_is_vulnerable(os:"6.2", file:"ntdll.dll", version:"6.2.9200.21428", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3045999") ||
  hotfix_is_vulnerable(os:"6.2", file:"ntdll.dll", version:"6.2.9200.17313", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3045999") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"clfs.sys", version:"6.1.7601.22981", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3045685") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"clfs.sys", version:"6.1.7601.18777", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3045685") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.23002", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3045999") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"ntdll.dll", version:"6.1.7601.18798", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3045999") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"clfs.sys", version:"6.0.6002.23639", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3045685") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"clfs.sys", version:"6.0.6002.19331", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3045685") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.23654", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3045999") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"ntdll.dll", version:"6.0.6002.19346", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3045999") ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"clfs.sys", version:"5.2.3790.5602", dir:"\system32", bulletin:bulletin, kb:"3045685") ||
  ("2003 R2" >!< productname && # Windows 2003 R2 is not affected
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"ntdll.dll", version:"5.2.3790.5583", dir:"\system32", bulletin:bulletin, kb:"3045999"))

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
