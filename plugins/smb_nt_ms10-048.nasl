#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(48285);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/04/23 21:35:39 $");

  script_cve_id("CVE-2010-1887", "CVE-2010-1894", "CVE-2010-1895", "CVE-2010-1896", "CVE-2010-1897");
  script_bugtraq_id(39630, 42206, 42210, 42245, 42250);
  script_osvdb_id(64057, 66979, 66981, 66982, 66983);
  script_xref(name:"MSFT", value:"MS10-048");

  script_name(english:"MS10-048: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2160329)");
  script_summary(english:"Checks version of Win32k.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Windows kernel is affected by several vulnerabilities that could
allow escalation of privileges."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a version of the Windows kernel
that is affected by one or more of the following vulnerabilities :

  - Improper valiation of an argument passed to a system
    call can result in a denial of service. (CVE-2010-1887)

  - Certain unspecified exceptions are not properly
    handled which could result in arbitrary code execution
    in the kernel. (CVE-2010-1894)

  - Memory is not properly allocated when making a copy
    from user mode, which could result in an elevation of
    privileges. (CVE-2010-1895)

  - Unspecified input from user mode is not properly
    validated, which could result in arbitrary code
    execution in the kernel. (CVE-2010-1896)

  - Unspecified parameters are not properly validated
    when creating a new window, which could result
    in arbitrary code execution in the kernel.
    (CVE-2010-1897)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-048");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS10-048';
kbs = make_list("2160329");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '2160329';

if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Win32k.sys", version:"6.1.7600.20738", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Win32k.sys", version:"6.1.7600.16617",                               dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Win32k.sys", version:"6.0.6002.22428", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Win32k.sys", version:"6.0.6002.18275",                               dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Win32k.sys", version:"6.0.6001.22716", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Win32k.sys", version:"6.0.6001.18496",                               dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2",                   file:"Win32k.sys", version:"5.2.3790.4730", min_version:"5.2.0.0",         dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Win32k.sys", version:"5.1.2600.6003", min_version:"5.1.0.0",         dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-048", value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
