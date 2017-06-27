#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45508);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_cve_id(
    "CVE-2010-0234",
    "CVE-2010-0235",
    "CVE-2010-0236",
    "CVE-2010-0237",
    "CVE-2010-0238",
    "CVE-2010-0481",
    "CVE-2010-0482",
    "CVE-2010-0810"
  );
  script_bugtraq_id(
    39297,
    39309,
    39318,
    39319,
    39320,
    39322,
    39323,
    39324
  );
  script_osvdb_id(63728, 63729, 63730, 63731, 63732, 63733, 63735, 63736);
  script_xref(name:"MSFT", value:"MS10-021");

  script_name(english:"MS10-021: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (979683)");
  script_summary(english:"Checks version of ntoskrnl.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel is affected by eight vulnerabilities, including
some that allow a local attacker to execute code with SYSTEM
privileges."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Windows kernel
that is affected by eight vulnerabilities :

  - A denial of service vulnerability exists in the Windows
    kernel due to the insufficient validation of registry
    keys passed to a Windows kernel system call.
    (CVE-2010-0234)

  - A denial of service vulnerability exists in the Windows
    kernel due to the manner in which the kernel processes
    the values of symbolic links. (CVE-2010-0235)

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to the manner in which memory is
    allocated when extracting a symbolic link from a registry
    key. An attacker who successfully exploited this
    vulnerability could run arbitrary code in kernel mode.
    (CVE-2010-0236)

  - An elevation of privilege vulnerability exists when the
    Windows kernel does not properly restrict symbolic link
    creation between untrusted and trusted registry hives. An
    attacker who successfully exploited this vulnerability
    could run arbitrary code in kernel mode. (CVE-2010-0237)

  - A denial of service vulnerability exists in the way
    that the Windows kernel validates registry keys.
    (CVE-2010-0238)

  - A denial of service vulnerability exists in the Windows
    kernel due to the way that the kernel resolves the real
    path for a registry key from its virtual path.
    (CVE-2010-0481)

  - A denial of service vulnerability exists in the Windows
    kernel due to the improper validation of specially
    crafted image files. (CVE-2010-0482)

  - A denial of service vulnerability exists in the Windows
    kernel due to the way that the kernel handles certain
    exceptions. (CVE-2010-0810)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-021");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

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

bulletin = 'MS10-021';
kbs = make_list("979683");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "979683";

if (
  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"ntoskrnl.exe", version:"6.1.7600.16539",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"ntoskrnl.exe", version:"6.1.7600.20655", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ntoskrnl.exe", version:"6.0.6000.17021",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"ntoskrnl.exe", version:"6.0.6000.21226", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ntoskrnl.exe", version:"6.0.6001.18427",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"ntoskrnl.exe", version:"6.0.6001.22636", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ntoskrnl.exe", version:"6.0.6002.18209",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"ntoskrnl.exe", version:"6.0.6002.22341", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 x86 and x64
  hotfix_is_vulnerable(os:"5.2",                   file:"ntoskrnl.exe", version:"5.2.3790.4666", min_version:"5.2.0.0",         dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.3670", min_version:"5.1.0.0",         dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.5938", min_version:"5.1.0.0",         dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"ntoskrnl.exe", version:"5.0.2195.7376", min_version:"5.0.0.0",         dir:"\system32", bulletin:bulletin, kb:kb)
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
