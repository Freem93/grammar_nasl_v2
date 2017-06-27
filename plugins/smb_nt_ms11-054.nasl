#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55570);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id(
    "CVE-2011-1874",
    "CVE-2011-1875",
    "CVE-2011-1876",
    "CVE-2011-1877",
    "CVE-2011-1878",
    "CVE-2011-1879",
    "CVE-2011-1880",
    "CVE-2011-1881",
    "CVE-2011-1882",
    "CVE-2011-1883",
    "CVE-2011-1884",
    "CVE-2011-1885",
    "CVE-2011-1886",
    "CVE-2011-1887",
    "CVE-2011-1888"
  );
  script_bugtraq_id(
    48587,
    48589,
    48590,
    48591,
    48592,
    48593,
    48594,
    48595,
    48596,
    48597,
    48599,
    48601,
    48603,
    48607
  );
  script_osvdb_id(
    73777,
    73778,
    73779,
    73780,
    73781,
    73782,
    73783,
    73784,
    73785,
    73786,
    73787,
    73788,
    73789,
    73790,
    73791
  );
  script_xref(name:"MSFT", value:"MS11-054");

  script_name(english:"MS11-054: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2555917)");
  script_summary(english:"Checks version of Win32k.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows kernel is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of the Windows kernel that is
affected by the following vulnerabilities :

  - Multiple privilege escalation vulnerabilities exist due
    to the way that Windows kernel-mode drivers manage
    driver objects. (CVE-2011-1874, CVE-2011-1875,
    CVE-2011-1876, CVE-2011-1877, CVE-2011-1878,
    CVE-2011-1879, CVE-2011-1880, CVE-2011-1881,
    CVE-2011-1882, CVE-2011-1883, CVE-2011-1884,
    CVE-2011-1885, CVE-2011-1887, CVE-2011-1888)

  - An information disclosure vulnerability exists due to
    the way that Windows kernel-mode drivers validate
    function parameters. (CVE-2011-1886)");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-054");
  script_set_attribute( attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/12");

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

bulletin = 'MS11-054';
kb = "2555917";

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
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.21744", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.17630", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.20983", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.16830", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.22653", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18475", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.22927", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Win32k.sys", version:"6.0.6001.18653", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.4872", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.6119", dir:"\system32", bulletin:bulletin, kb:kb)
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
