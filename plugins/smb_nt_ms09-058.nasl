#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42114);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-2515", "CVE-2009-2516", "CVE-2009-2517");
  script_bugtraq_id(36623, 36624, 36625);
  script_osvdb_id(58859, 58860, 58861);
  script_xref(name:"MSFT", value:"MS09-058");

  script_name(english:"MS09-058: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (971486)");
  script_summary(english:"Checks version of ntoskrnl.exe");

  script_set_attribute(attribute:"synopsis", value:"The Windows kernel is vulnerable to multiple buffer overflow attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Windows kernel that
is affected by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to the incorrect truncation of a 64-
    bit value to a 32-bit value.  An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs, view / change / delete data, or
    create new accounts with full user rights.
    (CVE-2009-2515)

  - An elevation of privilege vulnerability exists in the
    Windows kernel due to the incorrect truncation of a 64-
    bit value to a 32-bit value.  An attacker who
    successfully exploited this vulnerability could run
    arbitrary code in kernel mode. An attacker could then
    install programs, view / change / delete data, or
    create new accounts with full user rights.
    (CVE-2009-2516)

  - A denial of service vulnerability exists in the Windows
    kernel because of the way the kernel handles certain
    exceptions.  An attacker could exploit the
    vulnerability by running a specially crafted
    application causing the system to restart.
    (CVE-2009-2517)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-058");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-058';
kb = '971486';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / 2k8
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"ntoskrnl.exe", version:"6.0.6000.16901", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,  file:"ntoskrnl.exe", version:"6.0.6000.21101", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"ntoskrnl.exe", version:"6.0.6001.18304", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,  file:"ntoskrnl.exe", version:"6.0.6001.22489", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"ntoskrnl.exe", version:"6.0.6002.18082", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,  file:"ntoskrnl.exe", version:"6.0.6002.22191", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 x86 and x64
  hotfix_is_vulnerable(os:"5.2", file:"ntoskrnl.exe", version:"5.2.3790.4566", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.3610", min_version:"5.1.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"ntoskrnl.exe", version:"5.1.2600.5857", min_version:"5.1.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"ntoskrnl.exe", version:"5.0.2195.7319", min_version:"5.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
