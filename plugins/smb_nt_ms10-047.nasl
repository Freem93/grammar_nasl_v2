#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48284);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/02/19 14:53:29 $");

  script_cve_id("CVE-2010-1888", "CVE-2010-1889", "CVE-2010-1890");
  script_bugtraq_id(42211, 42213, 42221);
  script_osvdb_id(66988, 66989, 66990);
  script_xref(name:"MSFT", value:"MS10-047");

  script_name(english:"MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852)");
  script_summary(english:"Checks version of Ntoskrnl.exe");

  script_set_attribute(attribute:"synopsis", value:
"The Windows kernel is affected by several vulnerabilities that could
allow escalation of privileges.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Windows kernel
that is affected by one or more of the following vulnerabilities :

  - A race condition when creating certain types of kernel
    threads may allow a local attacker to execute arbitrary
    code in kernel mode and take complete control of the
    affected system. (CVE-2010-1888)

  - A double free vulnerability when the kernel initializes
    objects while handling certain errors may allow a local
    attacker to execute arbitrary code in kernel mode and
    take complete control of the affected system.
    (CVE-2010-1889)

  - A failure to properly validate access control lists on
    kernel objects may allow a local attacker to cause the
    system to become unresponsive and automatically
    restart. (CVE-2010-1890)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-047");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, Vista, 2008,
7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/11");

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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-047';
kbs = make_list("981852");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '981852';
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Ntoskrnl.exe", version:"6.1.7600.20738", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0,             file:"Ntoskrnl.exe", version:"6.1.7600.16617", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Ntoskrnl.exe", version:"6.0.6002.22420", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Ntoskrnl.exe", version:"6.0.6002.18267", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Ntoskrnl.exe", version:"6.0.6001.22707", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Ntoskrnl.exe", version:"6.0.6001.18488", min_version:"6.0.6001.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Ntoskrnl.exe", version:"5.1.2600.5973",  min_version:"5.1.0.0",         dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/MS10-047", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
