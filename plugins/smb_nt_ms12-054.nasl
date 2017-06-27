
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61529);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id(
    "CVE-2012-1850",
    "CVE-2012-1851",
    "CVE-2012-1852",
    "CVE-2012-1853"
  );
  script_bugtraq_id(54921, 54928, 54931, 54940);
  script_osvdb_id(84598, 84599, 84600, 84601);
  script_xref(name:"MSFT", value:"MS12-054");
  script_xref(name:"IAVA", value:"2012-A-0137");

  script_name(english:"MS12-054: Vulnerabilities in Windows Networking Components Could Allow Remote Code Execution (2733594)");
  script_summary(english:"Checks version of netapi32.dll and localspl.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is potentially affected by multiple code
execution vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is potentially affected by the following
vulnerabilities :

  - A denial of service vulnerability exists in Windows
    networking components.  The vulnerability is due to the
    service not properly handling specially crafted RAP
    requests. (CVE-2012-1850)

  - A remote code execution vulnerability exists in the
    Windows Print Spooler service that can allow a remote,
    unauthenticated attacker to execute arbitrary code on
    an affected system. (CVE-2012-1851)

  - A remote code execution vulnerability exists in the
    way that Windows networking components handle
    specially crafted RAP responses.
    (CVE-2012-1852, CVE-2012-1853)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-054");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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

bulletin = "MS12-054";
kbs = make_list("2705219","2712808");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
 # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"netapi32.dll", version:"6.1.7600.17056", min_version:"6.1.7600.16000",    dir:"\System32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"netapi32.dll", version:"6.1.7600.21256", min_version:"6.1.7600.20000",    dir:"\System32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"netapi32.dll", version:"6.1.7601.17887", min_version:"6.1.7601.17000",    dir:"\System32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"netapi32.dll", version:"6.1.7601.22044", min_version:"6.1.7601.21000",    dir:"\System32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"localspl.dll", version:"6.1.7600.17023", min_version:"6.1.7600.16000",    dir:"\System32", bulletin:bulletin, kb:"2712808") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"localspl.dll", version:"6.1.7600.21214",  min_version:"6.1.7600.20000",   dir:"\System32", bulletin:bulletin, kb:"2712808") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"localspl.dll", version:"6.1.7601.17841",  min_version:"6.1.7601.17000",   dir:"\System32", bulletin:bulletin, kb:"2712808") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"localspl.dll", version:"6.1.7601.21994",  min_version:"6.1.7601.21000",   dir:"\System32", bulletin:bulletin, kb:"2712808") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netapi32.dll", version:"6.0.6002.18659", min_version:"6.0.6002.18000",    dir:"\System32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"netapi32.dll", version:"6.0.6002.22887", min_version:"6.0.6002.22000",    dir:"\System32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"localspl.dll", version:"6.0.6002.18631", min_version:"6.0.6002.18000",    dir:"\System32", bulletin:bulletin, kb:"2712808") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"localspl.dll", version:"6.0.6002.22857", min_version:"6.0.6002.22000",    dir:"\System32", bulletin:bulletin, kb:"2712808") ||

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"netapi32.dll", version:"5.2.3790.5030",                                   dir:"\System32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"localspl.dll", version:"5.2.3790.5002",                                   dir:"\System32", bulletin:bulletin, kb:"2712808") ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"netapi32.dll", version:"5.1.2600.6260",                                   dir:"\system32", bulletin:bulletin, kb:"2705219") ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"localspl.dll", version:"5.1.2600.6226",                                   dir:"\system32", bulletin:bulletin, kb:"2712808")
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
