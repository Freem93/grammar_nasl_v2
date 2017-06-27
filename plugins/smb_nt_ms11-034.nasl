#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53391);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2011-0662", "CVE-2011-0665", "CVE-2011-0666", "CVE-2011-0667", "CVE-2011-0670",
                "CVE-2011-0671", "CVE-2011-0672", "CVE-2011-0673", "CVE-2011-0674", "CVE-2011-0675",
                "CVE-2011-0676", "CVE-2011-0677", "CVE-2011-1225", "CVE-2011-1226", "CVE-2011-1227",
                "CVE-2011-1228", "CVE-2011-1229", "CVE-2011-1230", "CVE-2011-1231", "CVE-2011-1232",
                "CVE-2011-1233", "CVE-2011-1234", "CVE-2011-1235", "CVE-2011-1236", "CVE-2011-1237",
                "CVE-2011-1238", "CVE-2011-1239", "CVE-2011-1240", "CVE-2011-1241", "CVE-2011-1242");
  script_bugtraq_id(47194, 47202, 47203, 47204, 47205, 47206, 47207, 47209, 47210, 47211, 47212,
                    47213, 47214, 47215, 47216, 47217, 47218, 47219, 47220, 47224, 47225, 47226,
                    47227, 47228, 47229, 47230, 47231, 47232, 47233, 47234);
  script_osvdb_id(
    71727,
    71728,
    71729,
    71730,
    71731,
    71732,
    71734,
    71735,
    71736,
    71737,
    71738,
    71739,
    71740,
    71741,
    71742,
    71743,
    71744,
    71745,
    71746,
    71747,
    71748,
    71749,
    71750,
    71751,
    71752,
    71753,
    71754,
    71755,
    71756,
    71757
  );
  script_xref(name:"MSFT", value:"MS11-034");

  script_name(english:"MS11-034: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2506223)");
  script_summary(english:"Checks version of Win32k.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows kernel is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of the Windows kernel that is
affected by the following types of vulnerabilities :

  - Several use-after-free vulnerabilities exist due to the
    way that Windows kernel-mode drivers manage kernel-mode
    driver objects. (CVE-2011-0662, CVE-2011-0665,
    CVE-2011-0666, CVE-2011-0667, CVE-2011-0670,
    CVE-2011-0671, CVE-2011-0672, CVE-2011-0674,
    CVE-2011-0675, CVE-2011-1234, CVE-2011-1235,
    CVE-2011-1236, CVE-2011-1237, CVE-2011-1238,
    CVE-2011-1239, CVE-2011-1240, CVE-2011-1241,
    CVE-2011-1242)

  - Several NULL pointer de-reference vulnerabilities exist
    due to the way that Windows kernel-mode drivers manage
    pointers to kernel-mode driver objects. (CVE-2011-0673,
    CVE-2011-0676, CVE-2011-0677, CVE-2011-1225,
    CVE-2011-1226, CVE-2011-1227, CVE-2011-1228,
    CVE-2011-1229, CVE-2011-1230, CVE-2011-1231,
    CVE-2011-1232, CVE-2011-1233)

An attacker with local access to the affected system can exploit these
issues to execute arbitrary code in kernel mode and take complete
control of the affected system."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-034");
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
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS11-034';
kb = "2506223";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.21673", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.17570", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.20914", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.16772", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.22601", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18417", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22867", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18612", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4841", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.6090", dir:"\system32", bulletin:bulletin, kb:kb)
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
