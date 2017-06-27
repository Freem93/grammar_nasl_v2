#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73982);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-1756", "CVE-2014-1808");
  script_bugtraq_id(67274, 67279);
  script_osvdb_id(106894, 106895);
  script_xref(name:"MSFT", value:"MS14-023");
  script_xref(name:"IAVB", value:"2014-B-0058");

  script_name(english:"MS14-023: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2961037)");
  script_summary(english:"Checks versions of several .dll files.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple vulnerabilities :

  - A vulnerability exists in the way that Windows loads
    .dll files that could allow remote code execution if
    a crafted .dll file is in the same directory as an
    Office file being opened. When exploiting this
    vulnerability, an attacker could gain the same user
    permissions as the current user. (Proofing tools in
    Office 2007 SP3, Office 2010 SP1/SP2 for Simplified
    Chinese, Proofing tools in Office 2013 SP0/SP1)

  - The remote Windows host is potentially affected by a
    vulnerability in the way Office handles responses to
    opening remote network Office files. When exploiting
    this vulnerability, an attacker could gain the access
    token used to authenticate the user on a Microsoft
    online service. (Office 2013 SP0/SP1)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-023");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
and 2013 RT.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-023';

kbs = make_list(
  "2961037",
  "2880463",
  "2878316",
  "2878284",
  "2767772"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
arch = get_kb_item_or_exit("SMB/ARCH");

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_ver = hotfix_check_office_version();

vuln = 0;
x86_path = hotfix_get_commonfilesdir();
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x64_path = hotfix_get_programfilesdirx86();
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');

# CVE-2014-1756
# Office 2013 SP0 or SP1
if (office_ver['15.0'])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
  {
    if (
      (hotfix_is_vulnerable(file:"msgren32.dll", version:"15.0.0.5", min_version:'15.0.0.0', path:x86_path + "\Microsoft Shared\PROOF", bulletin:bulletin, kb:"2880463")) ||
      (hotfix_is_vulnerable(file:"msgren32.dll", arch:"x64", version:"15.0.0.5", min_version:'15.0.0.0', path:x64_path + "\Common Files\Microsoft Shared\PROOF", bulletin:bulletin, kb:"2880463"))
    ) vuln++;
  }
}

# Office 2010 SP1 or SP2
if (office_ver['14.0'])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
  {
    if (
      (hotfix_is_vulnerable(file:"tcscconv.dll", version:"14.0.7120.5000", min_version:'14.0.0.0', path:x86_path + "\Microsoft Office\Office14\ADDINS", bulletin:bulletin, kb:"2878284")) ||
      (hotfix_is_vulnerable(file:"tcscconv.dll", arch:"x64", version:"14.0.7120.5000", min_version:'14.0.0.0', path:x64_path + "\Microsoft Office\Office14\ADDINS", bulletin:bulletin, kb:"2878284"))
    ) vuln++;
  }
}

# Office 2007 SP3
if (office_ver['12.0'])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {
    get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated");

    # File version check for 2007 SP3 unreliable, check registry.
    display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
    if (display_names)
    {
      simplifiedproof = FALSE;
      foreach item (keys(display_names))
      {
        if ('Microsoft Office Proof (Chinese (Simplified)) 2007' >< display_names[item])
        {
          item = item - 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/';
          item = item - '/DisplayName';
          ver = get_kb_item('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/' + item + '/DisplayVersion');
          if (ver =~ '^12.0.6612.1000$')
          {
            simplifiedproof = TRUE;
            break;
          }
        }
      }
      # Check for KB
      kb2767772 = FALSE;
      if (simplifiedproof)
      {
        foreach item (keys(display_names))
        {
          if ('Security Update for Microsoft Office 2007 suites (KB2767772)' >< display_names[item])
          {
            kb2767772 = TRUE;
            break;
          }
        }
        if (!kb2767772)
        {
          hotfix_add_report('\n  According to the registry, KB2767772 is missing.\n', bulletin:bulletin, kb:2767772);
          vuln++;
        }
      }
    }
  }
}

# CVE-2014-1808

# Office 2013 SP0 or SP1
if (office_ver['15.0'])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
  {
    if (
      (hotfix_is_vulnerable(file:"mso.dll", version:"15.0.4615.1000", min_version:'15.0.0.0', path:x86_path + "\Microsoft Shared\Office15", bulletin:bulletin, kb:"2878316")) ||
      (hotfix_is_vulnerable(file:"mso.dll", arch:"x64", version:"15.0.4615.1000", min_version:'15.0.0.0', path:x64_path + "\Common Files\Microsoft Shared\Office15", bulletin:bulletin, kb:"2878316"))
    ) vuln++;
  }
}

if (vuln)
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
