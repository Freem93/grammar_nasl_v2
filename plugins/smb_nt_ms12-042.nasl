#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59460);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2012-0217", "CVE-2012-1515");
  script_bugtraq_id(52820, 53856);
  script_osvdb_id(82849, 82850);
  script_xref(name:"EDB-ID", value:"20861");
  script_xref(name:"MSFT", value:"MS12-042");

  script_name(english:"MS12-042: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2711167)");
  script_summary(english:"Checks version of Ntoskrnl.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The Windows kernel is affected by multiple elevation of privilege
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a Windows kernel version that is affected
by multiple elevation of privilege vulnerabilities :

  - A vulnerability exists in the way that the Windows User
    Mode Scheduler handles system requests that can be
    exploited to execute arbitrary code in kernel mode.
    (CVE-2012-0217)

  - A vulnerability exists in the way that Windows handles
    BIOS memory that can be exploited to execute arbitrary
    code in kernel mode. (CVE-2012-1515)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS12-042");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for 32-bit versions of
Windows XP and 2003 as well as patches for 64-bit versions of Windows
7 and Server 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS12-042";
kbs = make_list("2707511", "2709715");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Ntoskrnl.exe", version:"5.1.2600.6223", dir:"\system32", bulletin:bulletin, kb:"2707511") ||

  # Windows 2003 x86
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Ntoskrnl.exe", version:"5.2.3790.4998",  dir:"\system32", bulletin:bulletin, kb:"2707511") ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"Ntoskrnl.exe", version:"6.1.7600.17017", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2709715") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"Ntoskrnl.exe", version:"6.1.7600.21207", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2709715") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Ntoskrnl.exe", version:"6.1.7601.17835", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:"2709715") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"Ntoskrnl.exe", version:"6.1.7601.21987", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:"2709715")
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
