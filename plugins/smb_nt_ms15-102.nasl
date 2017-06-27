#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85844);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2015-2524",
    "CVE-2015-2525",
    "CVE-2015-2528"
  );
  script_bugtraq_id(
    76587,
    76590,
    76653
  );
  script_osvdb_id(
    127203,
    127204,
    127205
  );
  script_xref(name:"MSFT", value:"MS15-102");
  script_xref(name:"IAVA", value:"2015-A-0215");

  script_name(english:"MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657)");
  script_summary(english:"Checks the version of schedsvc.dll or settingsync.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple elevation of privilege
vulnerabilities in Windows Task Management :

  - An elevation of privilege vulnerability exists due to a
    failure to properly validate and enforce impersonation
    levels. An authenticated, remote attacker can exploit
    this, via a specially crafted application, to bypass
    impersonation-level security checks and gain elevated
    privileges. (CVE-2015-2524)

  - An elevation of privilege vulnerability exists in
    Windows Task Scheduler due to improper verification of
    certain file system interactions. An authenticated,
    remote attacker can exploit this, via a specially
    crafted application, to execute arbitrary code in the
    security context of the local system. (CVE-2015-2525)

  - An elevation of privilege vulnerability exists due to a
    failure to properly validate and enforce impersonation
    levels. An authenticated, remote attacker can exploit
    this, via a specially crafted application, to bypass
    impersonation-level security checks and gain elevated
    privileges. CVE-2015-2528)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-102");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, 2012 R2, 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");

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

bulletin = 'MS15-102';

kbs = make_list('3084135', '3082089', '3081455');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

vuln = 0;

# KB 3084135
# Windows 7 for 32-bit Systems Service Pack 1
# Windows 7 for x64-based Systems Service Pack 1
# Windows 8 for 32-bit Systems
# Windows 8 for x64-based Systems
# Windows 8.1 for 32-bit Systems
# Windows 8.1 for x64-based Systems
# Windows Server 2008 R2 for x64-based Systems Service Pack 1
# Windows Server 2008 for 32-bit Systems Service Pack 2
# Windows Server 2008 for x64-based Systems Service Pack 2
# Windows Server 2012
# Windows Server 2012 R2
# Windows Vista Service Pack 2
# Windows Vista x64 Edition Service Pack 2
if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"schedsvc.dll", version:"6.3.9600.18001", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3084135") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"schedsvc.dll", version:" 6.2.9200.21579", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3084135") ||
  hotfix_is_vulnerable(os:"6.2", file:"schedsvc.dll", version:" 6.2.9200.17465", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3084135") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schedsvc.dll", version:" 6.1.7601.23154", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3084135") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schedsvc.dll", version:" 6.1.7601.18951", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3084135") ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schedsvc.dll", version:"6.0.6002.23774", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3084135") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schedsvc.dll", version:" 6.0.6002.19465", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3084135")
)
  vuln++;

# KB 3082089
# Windows 8 for 32-bit Systems
# Windows 8 for x64-based Systems
# Windows 8.1 for 32-bit Systems
# Windows 8.1 for x64-based Systems
# Windows Server 2012
# Windows Server 2012 R2
if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"settingsync.dll", version:"6.3.9600.17959", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3082089") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"settingsync.dll", version:"6.2.9200.21578", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3082089") ||
  hotfix_is_vulnerable(os:"6.2", file:"settingsync.dll", version:" 6.2.9200.17464", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3082089")
)
  vuln++;

# KB 3081455
# Windows 10 for 32-bit Systems
# Windows 10 for 64-bit Systems
if (
  hotfix_is_vulnerable(os:"10", sp:0, file:"Schedsvc.dll", version:"10.0.10240.16485", min_version:"10.0.10240.1600", dir:"\system32", bulletin:bulletin, kb:"3081455")
)
  vuln++;

if (vuln)
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
