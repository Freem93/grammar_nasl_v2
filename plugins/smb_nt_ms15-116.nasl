#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86823);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/06 19:24:46 $");

  script_cve_id(
    "CVE-2015-2503",
    "CVE-2015-6038",
    "CVE-2015-6091",
    "CVE-2015-6092",
    "CVE-2015-6093",
    "CVE-2015-6094"
  );
  script_bugtraq_id(
    77485,
    77489,
    77490,
    77491,
    77492,
    77493
  );
  script_osvdb_id(
    130050,
    130051,
    130052,
    130053,
    130054,
    130055
  );
  script_xref(name:"MSFT", value:"MS15-116");
  script_xref(name:"IAVA", value:"2015-A-0272");

  script_name(english:"MS15-116: Security Update for Microsoft Office to Address Remote Code Execution (3104540)");
  script_summary(english:"Checks the Office, SharePoint, and Skype versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Access,
Excel, InfoPath, OneNote, PowerPoint, Project, Publisher, Visio, Word,
Excel Viewer, Word Viewer, SharePoint Server, Office Compatibility
Pack, Office Web Apps, Skype for Business, or Lync installed that is
affected by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted Office file,
    resulting in execution of arbitrary code in the context
    of the current user. (CVE-2015-6038, CVE-2015-6091,
    CVE-2015-6092, CVE-2015-6093, CVE-2015-6094)

  - An elevation of privilege vulnerability exists when an
    attacker instantiates an affected Office application via
    a COM control. An attacker who successfully exploits
    this vulnerability can gain elevated privileges and
    break out of the Internet Explorer sandbox.
    (CVE-2015-2503)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-116");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, 2016; SharePoint Server 2007, 2010, 2013; Office
Compatibility Pack, Excel Viewer, Word Viewer, Office Web Apps 2010
and 2013, and Lync 2013 and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:access");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:pinyin_ime");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_sharepoint_installed.nbin", "microsoft_lync_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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
include("install_func.inc");

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-116';
kbs = make_list(
  2596614,
  2596770,
  2687406,
  2817478,
  2878230,
  2880506,
  2889915,
  2899473,
  2899516,
  2910978,
  2920680,
  2920698,
  2920726,
  2965313,
  3054793,
  3054978,
  3085477,
  3085511,
  3085548,
  3085551,
  3085552,
  3085561,
  3085561,
  3085584,
  3085594,
  3085614,
  3085634,
  3101359,
  3101360,
  3101364,
  3101365,
  3101367,
  3101370,
  3101371,
  3101496,
  3101499,
  3101506,
  3101507,
  3101509,
  3101510,
  3101512,
  3101513,
  3101514,
  3101521,
  3101525,
  3101526,
  3101529,
  3101533,
  3101543,
  3101544,
  3101553,
  3101554,
  3101555,
  3101558,
  3101559,
  3101560,
  3101564
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();
hcf_init = TRUE;

# Make sure the Correct version of Office is installed
global_var affectedime;
office_product_codes = make_list(
  '90140000-0028-0411-0000-0000000FF1CE', # Japan
  '90140000-0028-0412-0000-0000000FF1CE', # Korean
  '90140000-0028-0804-0000-0000000FF1CE', # Chinese
  '90140000-0028-0404-0000-0000000FF1CE'  # Taiwan
);
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
for (i=0; i < max_index(office_product_codes); i++)
{
  key = "SOFTWARE\Microsoft\Office\14.0\Common\InstalledPackages" + '\\' + office_product_codes[i]+ '\\';
  res = get_registry_value(handle:hklm, item:key);
  if ('Microsoft Office IME' >< res) affectedime = TRUE;
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2007_path, sps_2007_sp, sps_2007_edition;
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var installs, install, path, prod;

  sps_2013_path = NULL;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install['Product'] == "2007")
    {
      sps_2007_path = install['path'];
      sps_2007_sp = install['SP'];
      sps_2007_edition = install['Edition'];
    }
    else if (install["Product"] == "2010")
    {
      sps_2010_path = install['path'];
      sps_2010_sp = install['SP'];
      sps_2010_edition = install['Edition'];
    }
    else if (install['Product'] == "2013")
    {
      sps_2013_path = install['path'];
      sps_2013_sp = install['SP'];
      sps_2013_edition = install['Edition'];
      break;
    }
  }

  # Office Services and Web Apps
  ######################################################################
  # SharePoint Server 2007 SP3 - Excel Services
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6735.5000", path:path, bulletin:bulletin, kb:"3101559", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Excel Services
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7162.5000", path:path, bulletin:bulletin, kb:"3101525", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7162.5000", path:path, bulletin:bulletin, kb:"3085511", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013 SP1 - Excel Services
  # Sharepoint Server 2013 SP1 - Word Automation Services
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4771.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3101364", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
      vuln = TRUE;
    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4771.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3085477", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# Office Web Apps
######################################################################
function perform_owa_checks()
{
  local_var owa_installs, owa_install;
  local_var owa_2010_path, owa_2010_sp;
  local_var owa_2013_path, owa_2013_sp;
  local_var path;

  # Get installs of Office Web Apps
  owa_installs = get_installs(app_name:"Microsoft Office Web Apps");
  if (!empty_or_null(owa_installs))
  {
    foreach owa_install (owa_installs[1])
    {
      if (owa_install["Product"] == "2010")
      {
        owa_2010_path = owa_install["path"];
        owa_2010_sp = owa_install["SP"];
      }
      if (owa_install['Product'] == "2013")
      {
        owa_2013_path = owa_install['path'];
        owa_2013_sp = owa_install['SP'];
      }
    }
  }


  ######################################################################
  # Office Web Apps 2010 SP2
  ######################################################################
  if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
  {
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7162.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3101533", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"ExcelServicesEcs\bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4771.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3101367", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

# Generic Office Checks
function perform_office_checks()
{
  local_var office_vers, office_sp, path;
  local_var display_names, item;
  local_var office_version, x86path, x64path;

  office_vers = hotfix_check_office_version();
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"Mso.dll", version:"12.0.6735.5000", path:path, bulletin:bulletin, kb:"3101555", product:"Microsoft Office 2007 SP3") == HCF_OLDER)
        vuln = TRUE;
    }
    if (get_kb_item("SMB/Registry/Uninstall/Enumerated"))
    {
      display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
      if (display_names)
      {
        foreach item (keys(display_names))
        {
          if ('Microsoft Office IME (Japanese) 2007' >< display_names[item])
          {
            path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"Microsoft Shared\IME12\IMEJP");
            if (hotfix_check_fversion(file:"imjpcmnt.exe", version:"12.0.6735.5000", path:path, bulletin:bulletin, product:"Microsoft Office 2007 IME (Japanese)") == HCF_OLDER)
              vuln = TRUE;
            break;
          }
        }
      }
    }
  }
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (hotfix_check_fversion(file:"Wwlib.dll", version:"14.0.7162.5000", path:path, bulletin:bulletin, kb:"3101529", product:"Microsoft Office 2010") == HCF_OLDER)
        vuln = TRUE;
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"14.0"), value:"Microsoft Shared\Office14");
      if (hotfix_check_fversion(file:"Mso.dll", version:"14.0.7162.5000", path:path, bulletin:bulletin, kb:"3101521", product:"Microsoft Office 2010") == HCF_OLDER)
        vuln = TRUE;
    }
    if (affectedime)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"14.0"), value:"Microsoft Shared\IME14\IMESC");
      if (hotfix_check_fversion(file:"imsctip.dll", version:"14.0.7104.5000", path:path, bulletin:bulletin, product:"Microsoft Pinyin IME 2010") == HCF_OLDER)
        vuln = TRUE;
    }
  }
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && int(office_sp) <= 1)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"15.0"), value:"Microsoft Shared\Office15");
      if (hotfix_check_fversion(file:"Msores.dll", version:"15.0.4769.1000", path:path, bulletin:bulletin, kb:"3101360", product:"Microsoft Office 2013") == HCF_OLDER)
        vuln = TRUE;
    }
  }

  if (office_version["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && int(office_sp) <= 1)
    {
      path = hotfix_get_officeprogramfilesdir(officever:"16.0");
      x86path = hotfix_append_path(path:path, value:"Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\Office16");
      x64path = hotfix_append_path(path:path, value:"Microsoft Office\root\VFS\ProgramFilesCommonX64\Microsoft Shared\Office16");
      if (
        hotfix_check_fversion(file:"Mso99lres.dll", version:"16.0.4300.1000", channel:"MSI", channel_product:"Office", path:x86path, bulletin:bulletin, kb:"3101512", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Mso99lres.dll", version:"16.0.4300.1000", channel:"MSI", channel_product:"Office", path:x64path, bulletin:bulletin, kb:"3101512", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Mso99lres.dll", version:"16.0.6001.1038", channel:"Current", channel_product:"Office", path:x86path, bulletin:bulletin, kb:"3101512", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Mso99lres.dll", version:"16.0.6001.1038", channel:"Current", channel_product:"Office", path:x64path, bulletin:bulletin, kb:"3101512", product:"Microsoft Office 2016") == HCF_OLDER
      ) vuln = TRUE;
      
      if (
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.4300.1000", channel:"MSI", channel_product:"Office", path:x86path, bulletin:bulletin, kb:"3101514", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.4300.1000", channel:"MSI", channel_product:"Office", path:x64path, bulletin:bulletin, kb:"3101514", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.6001.1038", channel:"Current", channel_product:"Office", path:x86path, bulletin:bulletin, kb:"3101514", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.6001.1038", channel:"Current", channel_product:"Office", path:x64path, bulletin:bulletin, kb:"3101514", product:"Microsoft Office 2016") == HCF_OLDER
      ) vuln = TRUE;
    }
  }
}
# Individual and odd ball office products
function perform_office_product_checks()
{
  local_var checks, vwr_checks, compat_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Access Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "2596614"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5001", "kb", "3101544"),
    "15.0", make_array("sp", 1, "version", "15.0.4771.1000", "kb", "3085584"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4300.1000", "channel", "MSI", "kb", "2910978"),
      make_array("sp", 0, "version", "16.0.6001.1038", "channel", "Current", "kb", "2910978")
    )
  );
  if (hotfix_check_office_product(product:"Access", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "3101554"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "3101543"),
    "15.0", make_array("sp", 1, "version", "15.0.4771.1000", "kb", "3101499"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4300.1001", "channel", "MSI", "kb", "3101510"),
      make_array("sp", 0, "version", "16.0.6001.1038", "channel", "Current", "kb", "3101510")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # InfoPath Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "2687406"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "2878230"),
    "15.0", make_array("sp", 1, "version", "15.0.4763.1000", "kb", "3054793")
  );
  if (hotfix_check_office_product(product:"InfoPath", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # OneNote Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "2889915"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "3054978"),
    "15.0", make_array("sp", 1, "version", "15.0.4763.1000", "kb", "3101371"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4300.1001", "channel", "MSI", "kb", "2920726"),
      make_array("sp", 0, "version", "16.0.6001.1038", "channel", "Current", "kb", "2920726")
    )
  );
  if (hotfix_check_office_product(product:"OneNote", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "3085548"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "3085594"),
    "15.0", make_array("sp", 1, "version", "15.0.4771.1000", "kb", "3101359"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4300.1001", "channel", "MSI", "kb", "3101509"),
      make_array("sp", 0, "version", "16.0.6001.1038", "channel", "Current", "kb", "3101509")
    )
  );
  if (hotfix_check_office_product(product:"PowerPoint", checks:checks, bulletin:bulletin))
    vuln = TRUE;  

  ######################################################################
  # Project Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "2596770"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "3085614"),
    "15.0", make_array("sp", 1, "version", "15.0.4771.1000", "kb", "3101506"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4300.1000", "channel", "MSI", "kb", "2920698"),
      make_array("sp", 0, "version", "16.0.6001.1038", "channel", "Current", "kb", "2920698")
    )
  );
  if (hotfix_check_office_product(product:"Project", checks:checks, bulletin:bulletin))
    vuln = TRUE;  

  ######################################################################
  # Publisher Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "2880506"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "2817478"),
    "15.0", make_array("sp", 1, "version", "15.0.4763.1000", "kb", "3085561"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4300.1000", "channel", "MSI", "kb", "2920680"),
      make_array("sp", 0, "version", "16.0.6001.1038", "channel", "Current", "kb", "2920680")
    )
  );
  if (hotfix_check_office_product(product:"Publisher", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "3085552"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "2965313"),
    "15.0", make_array("sp", 1, "version", "15.0.4771.1000", "kb", "3101370"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4300.1001", "channel", "MSI", "kb", "3101513"),
      make_array("sp", 0, "version", "16.0.6001.1038", "channel", "Current", "kb", "3101513")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6735.5000", "kb", "3101560")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8421.0", "kb", "3101564")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel and Word Compatibility pack
  ######################################################################
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "3101558")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:compat_checks, bulletin:bulletin))
    vuln = TRUE;

  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6735.5000", kb: "3085551", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }
}

function perform_visio_checks()
{
  local_var installs,install,share,path,version;

  # Preconditions
  installs = get_kb_list("SMB/Office/Visio/*/VisioPath");
  if(isnull(installs))
    return;

  share = hotfix_path2share(path:path);
  if(!is_accessible_share(share:share))
    return;

  # Visio checks
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Visio/' - '/VisioPath';
    if ("12.0" >!< version && "14.0" >!< version && "15.0" >!< version && "16.0" >!< version)
      continue;
    path = installs[install];
    if ("12.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"12.0.6735.5000", min_version:"12.0.6000.0", bulletin:bulletin, kb:"3101553"))
      vuln = TRUE;
    if ("14.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.7162.5000", min_version:"14.0.6500.0", bulletin:bulletin, kb:"3101526"))
      vuln = TRUE;
    if ("15.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"15.0.4771.1000", min_version:"15.0.6000.0", bulletin:bulletin, kb:"3101365"))
      vuln = TRUE;
    if ("16.0" >< version && 
      (
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.4300.1000", channel:"MSI", channel_product:"Visio", bulletin:bulletin, kb:"3101507") ||
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.6001.1038", channel:"Current", channel_product:"Visio", bulletin:bulletin, kb:"3101507")
      )
    ) vuln = TRUE;
  }
}

######################################################################
# Lync checks
######################################################################
function perform_lync_checks()
{
  local_var lync_count, lync_installs, lync_install;

  lync_count = get_install_count(app_name:"Microsoft Lync");

  # Nothing to do
  if (int(lync_count) <= 0)
    return;

  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {
    # Lync 2013
    if (lync_install["version"] =~ "^15\.0\." && "Server" >!< lync_install["Product"])
    {
      if (hotfix_check_fversion(file:"Lync.exe", version:"15.0.4771.1001", min_version:"15.0.4569.1503", path:lync_install["path"], bulletin:bulletin, kb:"3101496", product:"Microsoft Lync 2013 (Skype for Business)") == HCF_OLDER)
        vuln++;
    }
    # Skype for Business 2016
    else if (lync_install["version"] =~ "^16\.0\." && "Server" >!< lync_install["Product"])
    {
      if (
        (hotfix_check_fversion(file:"Lync.exe", version:"16.0.4300.1001", channel:"MSI", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3085634", product:"Skype for Business 2016") == HCF_OLDER) ||
        (hotfix_check_fversion(file:"Lync.exe", version:"16.0.6001.1038", channel:"Current", channel_product:"Lync", path:lync_install["path"], bulletin:bulletin, kb:"3085634", product:"Skype for Business 2016") == HCF_OLDER)
      ) vuln++;
    }
  }
}

perform_sharepoint_checks();
perform_owa_checks();
perform_office_checks();
perform_office_product_checks();
perform_visio_checks();
perform_lync_checks();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
