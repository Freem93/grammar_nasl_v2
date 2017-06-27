#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58659);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/12/22 20:32:44 $");

  script_cve_id("CVE-2012-0158");
  script_bugtraq_id(52911);
  script_osvdb_id(81125);
  script_xref(name:"EDB-ID", value:"18780");
  script_xref(name:"MSFT", value:"MS12-027");

  script_name(english:"MS12-027: Vulnerability in Windows Common Controls Could Allow Remote Code Execution (2664258)");
  script_summary(english:"Checks for kill bit.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"A memory corruption issue exists in Windows common controls,
specifically within the MSCOMCTL.TreeView, MSCOMCTL.ListView2,
MSCOMCTL.TreeView2, and MSCOMCTL.ListView controls component of
MSCOMCTL.OCX, due to improper sanitization of user-supplied input. An
unauthenticated, remote attacker can exploit this issue by convincing
a user to view a specially crafted web page, resulting in the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-027");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, 2007 and
2010; Office 2003 Web Components; SQL Server 2000, 2005, 2005 Express
Edition, 2008, and 2008 R2; BizTalk Server 2002; Commerce Server 2002,
2007, 2009, and 2009 R2; Microsoft Visual FoxPro 8.0 and 9.0; and
Visual Basic 6.0 Runtime.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS12-027 MSCOMCTL ActiveX Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_components");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_foxpro");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:commerce_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies(
    "smb_hotfixes.nasl",
    "ms_bulletin_checks_possible.nasl",
    "mssql_version.nasl",
    "commerce_server_installed.nasl",
    "biztalk_server_installed.nasl",
    "foxpro_installed.nasl",
    "office_installed.nasl"
  );
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
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-027';
kbs = make_list(
  '983807',
  '983808',
  '983809',
  '2597112',
  '2598039',
  '2598041',
  '2641426',
  '2645025',
  '2647488',
  '2647490',
  '2655547',
  '2658674',
  '2658676',
  '2658677'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Uninstall/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init');

clsids = make_list(
  '{bdd1f04b-858b-11d1-b16a-00c0f0283628}',
  '{996BF5E0-8044-4650-ADEB-0B013914E99C}',
  '{C74190B6-8589-11d1-B16A-00C0F0283628}',
  '{9181DC5F-E07D-418A-ACA6-8EEA1ECB8E9E}'
);

activex_report = NULL;
vuln = 0;

foreach clsid (clsids)
{
  # Make sure the control is installed
  file = activex_get_filename(clsid:clsid);
  if (isnull(file) || !file) continue;

  # Get its version
  version = activex_get_fileversion(clsid:clsid);
  if (!version) version = 'unknown';

  if ((version != 'unknown' && ver_compare(ver:version, fix:'6.1.98.33') < 0) && activex_get_killbit(clsid:clsid) == 0)
  {
    vuln++;
    if (!isnull(activex_report)) activex_report += '\n';
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

biztalk_editions = make_list();
biztalk_installs = get_installs(app_name:"BizTalk Server");
if (!empty_or_null(biztalk_installs[1]))
{
  foreach biztalk_install (biztalk_installs[1])
    biztalk_editions = make_list(biztalk_editions, biztalk_install['Product Name']);
}

uninst_array = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

foreach item (keys(uninst_array))
{
  name = uninst_array[item];

  if (name == 'Microsoft Office 2003 Web Components')
  {
    # determine if this is an 11.x or a 12.x
    ver_key = item - "DisplayName";
    ver_key += "DisplayVersion";
    owc_ver = get_kb_item_or_exit(ver_key);

   if (
     # OWC 2003 SP3 (11.0.8173.0)
     owc_ver =~ "^11\." &&
     ver_compare(ver:owc_ver, fix:'11.0.8173.0', strict:FALSE) >= 0
   )
     owc2003_installed = TRUE;
   else if (
     # OWC 2003 for 2007 SP2 (12.0.6425.1000)
     # OWC 2003 for 2007 SP3 (12.0.6607.1000); note this
     # branch is vuln and there's no need for an upper
     # boundary until (and if) an SP4 is released.
     owc_ver =~ "^12\." &&
     ver_compare(ver:owc_ver, fix:'12.0.6425.1000', strict:FALSE) >= 0
   )
     owc2003_for_office2007_installed = TRUE;

    break;
  }
}

if (vuln > 0 || analysis_svcs_installed)
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  # If the ActiveX stuff looks unpatched, try to determine which KBs are missing
  if (vuln > 0)
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

  if (office_version['11.0'] || owc2003_installed)
  {
    flag = TRUE;
    if (office_version['11.0'])
    {
      sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(sp) && sp < 3) flag = FALSE; # < SP3 not reported
    }

    if (flag)
    {
      # KB923618 is Office 2003 SP3. KB2597112 will fail to install unless it's present, though it
      # doesn't make it clear that the failure is due to a lack of SP3
      prod_info +=
        '\n\nProduct        : Office 2003 / Office 2003 Web components' +
        '\nMissing update : KB2597112 (prerequisite: KB923618)';
      hotfix_add_report(bulletin:bulletin, kb:'2597112');
    }
  }
  if (office_version['12.0'] || owc2003_for_office2007_installed)
  {
    # If Office 2003 Web Components is ver. 12.x a different KB applies
    prod_info +=
      '\n\nProduct        : Office 2007 / Office 2003 Web Components' +
      '\nMissing update : KB2598041 (prerequisite: KB937961)';
    hotfix_add_report(bulletin:bulletin, kb:'2598041');
  }
  if (office_version['14.0'] && office_bitness != 'x64')
  {
    prod_info +=
      '\n\nProduct        : Office 2010' +
      '\nMissing update : KB2598039';
    hotfix_add_report(bulletin:bulletin, kb:'2598039');
  }
  if (vfp8_installed)
  {
    prod_info +=
      '\n\nProduct        : Visual FoxPro 8.0' +
      '\nMissing update : KB2647488';
    hotfix_add_report(bulletin:bulletin, kb:'2647488');
  }
  if (vfp9_installed)
  {
    prod_info +=
      '\n\nProduct        : Visual FoxPro 9.0' +
      '\nMissing update : KB2647490';
    hotfix_add_report(bulletin:bulletin, kb:'2647490');
  }
  if (vb6_installed)
  {
    # KB290887 is VB 6.0 Runtime SP6
    prod_info +=
      '\n\nProduct        : Visual Basic 6.0 Runtime' +
      '\nMissing update : KB2641426 (prerequisite: KB290887)';
    hotfix_add_report(bulletin:bulletin, kb:'2641426');
  }
  if ('2009 R2' >< commerce_edition)
  {
    prod_info +=
      '\n\nProduct        : Commerce Server 2009 R2' +
      '\nMissing update : KB2658676';
    hotfix_add_report(bulletin:bulletin, kb:'2658676');
  }
  else if ('2009' >< commerce_edition)
  {
    prod_info +=
      '\n\nProduct        : Commerce Server 2009' +
      '\nMissing update : KB2655547';
    hotfix_add_report(bulletin:bulletin, kb:'2655547');
  }
  if ('2007' >< commerce_edition)
  {
    prod_info +=
      '\n\nProduct        : Commerce Server 2007' +
      '\nMissing update : KB2658677';
    hotfix_add_report(bulletin:bulletin, kb:'2658677');
  }
  if ('2002' >< commerce_edition)
  {
    prod_info +=
      '\n\nProduct        : Commerce Server 2002' +
      '\nMissing update : KB2658674';
    hotfix_add_report(bulletin:bulletin, kb:'2658674');
  }
  if (max_index(biztalk_editions) > 0)
  {
    foreach biztalk_edition (biztalk_editions)
    {
      if ('2002' >< biztalk_edition)
      {
        prod_info +=
          '\n\nProduct        : BizTalk Server 2002' +
          '\nMissing update : KB2645025';
        hotfix_add_report(bulletin:bulletin, kb:'2645025');
      }
    }
  }
}

# the only other things to check are sql server 2000 and sql server 2000 analysis services.
# if neither are installed and the activex stuff is not vulnerable, there's no need to do any further testing
if (vuln == 0 && isnull(analysispath) && isnull(sql_ver_list)) exit(0, 'The host is not affected.');

if (!is_accessible_share()) exit(1, 'is_accessible_share() failed.');

# SQL Server 2000 Analysis Services
if (
  analysispath &&
  hotfix_is_vulnerable(path:analysispath, file:"Msmdadin.dll", version:"8.0.0.2302", min_version:"8.0.0.0", bulletin:bulletin, kb:"983807")
)
{
  vuln++;

  if (!isnull(activex_report))
  {
    prod_info +=
      '\n\nProduct        : SQL Server 2000 Analysis Services' +
      '\nMissing update : KB983807';
  }
}

foreach item (keys(sql_ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  # SQL Server 2000
  # GDR
  if (hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2000.80.2065.0", min_version:"2000.80.2000.0", bulletin:bulletin, kb:"983808"))
  {
    vuln++;

    if (!isnull(activex_report))
    {
      prod_info +=
        '\n\nProduct        : SQL Server 2000' +
        '\nMissing update : KB983808';
    }
  }
   # QFE
  else if(hotfix_is_vulnerable(path:sqlpath, file:"Sqlservr.exe", version:"2000.80.2301.0", min_version:"2000.80.2100.0", bulletin:bulletin, kb:"983809"))
  {
    vuln++;

    if (!isnull(activex_report))
    {
      prod_info +=
        '\n\nProduct        : SQL Server 2000' +
        '\nMissing update : KB983809';
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
