#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61535);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2012-1856");
  script_bugtraq_id(54948);
  script_osvdb_id(84593);
  script_xref(name:"MSFT", value:"MS12-060");

  script_name(english:"MS12-060: Vulnerability in Windows Common Controls Could Allow Remote Code Execution (2720573)");
  script_summary(english:"Checks for kill bit");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"There is an unspecified remote code execution vulnerability in Windows
common controls, which is included in several Microsoft products. An
attacker could exploit this by tricking a user into viewing a
maliciously crafted web page, resulting in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524144/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS12-060");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office 2003,
2007, and 2010, Office 2003 Web Components, Microsoft SQL Server 2000,
Microsoft SQL Analysis Services 2000, Microsoft Commerce Server 2002,
2007, and 2009, Microsoft Host Integration Server 2004, Microsoft
Visual Fox Pro 8.0 and 9.0, and Visual Basic 6.0 Runtime.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:commerce_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:host_integration_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_foxpro");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_components");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "mssql_version.nasl", "commerce_server_installed.nasl", "foxpro_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_activex_func.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-060';
kbs = make_list(
  '983811',
  '983812',
  '983813',
  '2597986',
  '2687441',
  '2726929',
  '2708437',
  '2708940',
  '2708941',
  '2711207',
  '2716389',
  '2716390',
  '2716392',
  '2716393'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Uninstall/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init');

clsids = make_list(
  '{1EFB6596-857C-11D1-B16A-00C0F0283628}',# MSComCtl.ocx (TabStrip)
  '{24B224E0-9545-4A2F-ABD5-86AA8A849385}',# MSComCtl.ocx (TabStrip2)
  '{9ED94440-E5E8-101B-B9B5-444553540000}' # Comctl32.ocx (TabStrip)
);

activex_report = NULL;
comctl132_vuln = FALSE;
mscomctl_vuln = FALSE;
vuln = FALSE;

foreach clsid (clsids)
{
  # Make sure the control is installed
  file = activex_get_filename(clsid:clsid);
  if (isnull(file) || !file) continue;

  # Get its version
  version = activex_get_fileversion(clsid:clsid);
  if (!version) version = 'unknown';

  if (
       activex_get_killbit(clsid:clsid) == 0 &&
       (
         (version =~ "^6\.0\." &&
          ver_compare(ver:version, fix:'6.0.98.34') < 0) ||
         (version =~ "^6\.1\." &&
          ver_compare(ver:version, fix:'6.1.98.34') < 0)
       )
     )
  {
    vuln = TRUE;
    if (clsid == '{9ED94440-E5E8-101B-B9B5-444553540000}')
      comctl132_vuln = TRUE;
    else mscomctl_vuln = TRUE;

    if(!isnull(activex_report)) activex_report += '\n';
    activex_report +=
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version;
  }
}

activex_end();

analysis_svcs_installed = !isnull(get_kb_item('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Microsoft SQL Server 2000 Analysis Services/DisplayName'));
sql_ver_list = get_kb_list("mssql/installs/*/SQLVersion");
analysispath = NULL;
vfp8_installed = !isnull(get_kb_item('SMB/VFP8.0/path'));
vfp9_installed = !isnull(get_kb_item('SMB/VFP9.0/path'));

commerce_edition = get_kb_item('SMB/commerce_server/productname');
vb6_installed = FALSE;
office_version = hotfix_check_office_version();
owc2003_installed = FALSE;
his2004_installed = FALSE;

foreach name (get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName'))
{
  if (name == 'Microsoft Office 2003 Web Components')
    owc2003_installed = TRUE;
  if (name == 'Microsoft Host Integration Server 2004')
    his2004_installed = TRUE;

  # break early if possible
  if(owc2003_installed == TRUE && his2004_installed == TRUE)
    break;
}

if (vuln || analysis_svcs_installed)
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  # If the ActiveX stuff looks unpatched, try to determine which KBs are missing
  if (vuln)
  {
    if (!isnull(get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\VisualStudio\6.0\Setup\Microsoft Visual Basic\ProductDir")))
      vb6_installed = TRUE;
  }

  # determine if 32 or 64-bit office is installed. this value is reportedly whenever office 2010 is installed, even if outlook is not installed
  if (office_version['14.0'])
    office_bitness = get_registry_value(handle:hklm, item:"Software\Microsoft\Office\14.0\Outlook\Bitness");

  # get the SQL Server 200 Analysis Services path if it looks like it's installed
  if (analysis_svcs_installed)
  {
    analysispath = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft SQL Server 2000 Analysis Services\InstallLocation");

    if (analysispath)
      analysispath += "\bin";
  }

  RegCloseKey(handle:hklm);
  close_registry();
}

prod_info = NULL;

if (vuln)
{
  activex_report = 'The following vulnerable controls do not have the kill bit set :\n' + activex_report;
  prod_info = NULL;

  if ((office_version['11.0'] || owc2003_installed) && mscomctl_vuln)
  {
    # KB923618 is Office 2003 SP3. KB2726929 will fail to install unless it's present, though it
    # doesn't make it clear that the failure is due to a lack of SP3
    prod_info +=
      '\n' +
      '\n  Product        : Office 2003 / Office 2003 Web components' +
      '\n  Missing Update : KB2726929 (prerequisite: KB923618)';
    hotfix_add_report(bulletin:bulletin, kb:'2726929');
  }
  if (office_version['12.0'] && mscomctl_vuln)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Office 2007' +
      '\n  Missing Update : KB2687441';
    hotfix_add_report(bulletin:bulletin, kb:'2687441');
  }
  if (office_version['14.0'] && office_bitness != 'x64' && mscomctl_vuln)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Office 2010' +
      '\n  Missing Update : KB2597986';
    hotfix_add_report(bulletin:bulletin, kb:'2597986');
  }
  if (vfp8_installed)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Visual FoxPro 8.0' +
      '\n  Missing Update : KB2708940';
    hotfix_add_report(bulletin:bulletin, kb:'2708940');
  }
  if (vfp9_installed)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Visual FoxPro 9.0' +
      '\n  Missing Update : KB2708941';
    hotfix_add_report(bulletin:bulletin, kb:'2708941');
  }
  if (vb6_installed)
  {
    # KB290887 is VB 6.0 Runtime SP6
    prod_info +=
      '\n' +
      '\n  Product        : Visual Basic 6.0 Runtime' +
      '\n  Missing Update : KB2708437 (prerequisite: KB290887)';
    hotfix_add_report(bulletin:bulletin, kb:'2708437');
  }
  if (his2004_installed && comctl132_vuln)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Host Integration Server 2004' +
      '\n  Missing Update : KB2711207';
    hotfix_add_report(bulletin:bulletin, kb:'2711207');
  }

  if ('2009 R2' >< commerce_edition && mscomctl_vuln)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Commerce Server 2009 R2' +
      '\n  Missing Update : KB2716393';
    hotfix_add_report(bulletin:bulletin, kb:'2716393');
  }
  else if ('2009' >< commerce_edition && mscomctl_vuln)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Commerce Server 2009' +
      '\n  Missing Update : KB2716392';
    hotfix_add_report(bulletin:bulletin, kb:'2716392');
  }
  if ('2007' >< commerce_edition && mscomctl_vuln)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Commerce Server 2007' +
      '\n  Missing Update : KB2716390';
    hotfix_add_report(bulletin:bulletin, kb:'2716390');
  }
  if ('2002' >< commerce_edition && mscomctl_vuln)
  {
    prod_info +=
      '\n' +
      '\n  Product        : Commerce Server 2002' +
      '\n  Missing Update : KB2716389';
    hotfix_add_report(bulletin:bulletin, kb:'2716389');
  }
}

# the only other things to check are sql server 2000 and sql server 2000 analysis services.
# if neither are installed and the activex stuff is not vulnerable, there's no need to do any further testing
if (!vuln && isnull(analysispath) && isnull(sql_ver_list))
  exit(0, 'The host is not affected.');

if (!is_accessible_share())
  audit(AUDIT_FN_FAIL, 'is_accessible_share()');

# SQL Server 2000 Analysis Services
if (
  analysispath &&
  hotfix_is_vulnerable(path:analysispath, file:"Msmdadin.dll", version:"8.0.0.2304", min_version:"8.0.0.0", bulletin:bulletin, kb:"983813")
)
{
  vuln = TRUE;

  if (!isnull(activex_report))
  {
    prod_info +=
      '\n' +
      '\n  Product        : SQL Server 2000 Analysis Services' +
      '\n  Missing Update : KB983813';
  }
}

foreach item (keys(sql_ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  # GDR
  if (hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2000.80.2066.0", min_version:"2000.80.2000.0", bulletin:bulletin, kb:"983812"))
  {
    vuln = TRUE;

    if (!isnull(activex_report))
    {
      prod_info +=
        '\n' +
        '\n  Product        : SQL Server 2000' +
        '\n  Missing Update : KB983812';
    }
  }
   # QFE
  else if(hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2000.80.2305.0", min_version:"2000.80.2100.0", bulletin:bulletin, kb:"983811"))
  {
    vuln = TRUE;

    if (!isnull(activex_report))
    {
      prod_info +=
        '\n' +
        '\n  Product        : SQL Server 2000' +
        '\n  Missing Update : KB983811';
    }
  }
}

if (vuln)
{
  if (isnull(prod_info)) exit(0, "None of the Microsoft KBs applies even though at least one of the controls is in use, possibly from a third-party application.");

  if (!isnull(activex_report))
  {
    activex_report +=
      '\n\nNessus determined these controls are being used by the following applications :' +
      prod_info;

    if (hotfix_get_report())
      hotfix_add_report('\n' + activex_report, bulletin:bulletin);
    else
      hotfix_add_report(activex_report, bulletin:bulletin);
  }

  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
