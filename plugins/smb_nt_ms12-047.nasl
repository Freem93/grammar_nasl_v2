#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59910);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2012-1890", "CVE-2012-1893");
  script_bugtraq_id(54285, 54302);
  script_osvdb_id(83658, 83659);
  script_xref(name:"MSFT", value:"MS12-047");

  script_name(english:"MS12-047: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2718523)");
  script_summary(english:"Checks version of win32k.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by multiple privilege escalation
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is affected by several vulnerabilities in the
kernel-mode drivers that could allow elevation of privilege :

  - Flaws in the way the Windows kernel-mode drivers handles
    specific keyboard layouts could be exploited to execute
    arbitrary code in kernel mode. (CVE-2012-1890)

  - Windows kernel-mode drivers do not properly validate
    parameters when creating a hook procedure, which could
    be exploited to execute arbitrary code in kernel mode.
    (CVE-2012-1893)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/windows-kernel-readlayoutfile");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523557/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-047");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-047';
kb = '2718523';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

vuln = FALSE;

#######################
# KB2686509           #
#######################
winver = get_kb_item('SMB/WindowsVersion');
spver = get_kb_item('SMB/CSDVersion');
prodname = get_kb_item('SMB/ProductName');
if (spver)
  spver = int(ereg_replace(string:spver, pattern:'.*Service Pack ([0-9]).*', replace:"\1"));
if (
  winver && spver && prodname &&
  (
    (winver == '5.2' && spver == 2) ||
    (winver == '5.1' && spver == 3)
  )
)
{
  if (winver == '5.2' && spver == 2 && 'XP' >< prodname)
    reg_name = "SOFTWARE\Microsoft\Updates\Windows XP Version 2003\SP3\KB2686509\Description";
  else if (winver == '5.2' && spver == 2)
    reg_name = "SOFTWARE\Microsoft\Updates\Windows Server 2003\SP3\KB2686509\Description";
  else if (winver == '5.1' && spver == 3)
    reg_name = "SOFTWARE\Microsoft\Updates\Windows XP\SP4\KB2686509\Description";

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  desc = get_registry_value(handle:hklm, item:reg_name);
  RegCloseKey(handle:hklm);
  close_registry();

  if (isnull(desc))
  {
    report =
    '\nAccording to the registry, KB2686509 is missing.' +
    '\nTo obtain complete protection from the vulnerability addressed by\n' +
    'this security release, you must install this update with KB2686509\n';
    hotfix_add_report(report, bulletin:bulletin, kb:"2686509");
    vuln = TRUE;
  }
}


if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.22016", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Win32k.sys", version:"6.1.7601.17860", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.21231", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Win32k.sys", version:"6.1.7600.17039", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.22876", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Win32k.sys", version:"6.0.6002.18647", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Win32k.sys", version:"5.2.3790.5019", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Win32k.sys", version:"5.1.2600.6244", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  vuln = TRUE;
}

hotfix_check_fversion_end();

if (vuln)
{
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
