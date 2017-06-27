#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44425);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0233", "CVE-2010-0232");
  script_bugtraq_id(37864, 38044);
  script_osvdb_id(61854, 62259);
  script_xref(name:"MSFT", value:"MS10-015");

  script_name(english:"MS10-015: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (977165)");
  script_summary(english:"Checks version of ntoskrnl.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel is affected by two vulnerabilities allowing a
local attacker to execute code with SYSTEM privileges."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Windows kernel
that is affected by two vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    kernel due to the way it handles certain exceptions. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs, view / change / delete
    data, or create new accounts with full user rights.
    (CVE-2010-0232)

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to a double free condition. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. An attacker
    could then install programs, view / change / delete
    data, or create new accounts with full user rights.
    (CVE-2010-0233)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-015");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008 and 7."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows SYSTEM Escalation via KiTrap0D');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-015';
kbs = make_list("977165");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "977165";

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", arch:"x86", sp:0, file:"ntoskrnl.exe", version:"6.1.7600.16481",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x86", sp:0, file:"ntoskrnl.exe", version:"6.1.7600.20591", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ntoskrnl.exe", version:"6.0.6000.16973",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ntoskrnl.exe", version:"6.0.6000.21175", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ntoskrnl.exe", version:"6.0.6001.18377",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ntoskrnl.exe", version:"6.0.6001.22577", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ntoskrnl.exe", version:"6.0.6002.18160",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ntoskrnl.exe", version:"6.0.6002.22283", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 x86 and x64
  hotfix_is_vulnerable(os:"5.2",                   file:"ntoskrnl.exe", version:"5.2.3790.4637",  min_version:"5.2.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.3654",  min_version:"5.1.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.5913",  min_version:"5.1.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"ntoskrnl.exe", version:"5.0.2195.7364",  min_version:"5.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb)
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
