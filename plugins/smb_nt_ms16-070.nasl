#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91611);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 14:38:51 $");

  script_cve_id(
    "CVE-2016-0025",
    "CVE-2016-3233",
    "CVE-2016-3234",
    "CVE-2016-3235"
  );
  script_bugtraq_id(
    91089,
    91091,
    91095,
    91096
  );
  script_osvdb_id(
    139969,
    139970,
    139971,
    139972
  );
  script_xref(name:"MSFT", value:"MS16-070");
  script_xref(name:"IAVA", value:"2016-A-0148");

  script_name(english:"MS16-070: Security Update for Microsoft Office (3163610)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities in Microsoft Office :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory.  An
    unauthenticated, remote attacker can exploit these by
    convincing a user to open a specially crafted file or
    visit a website that hosts such a file, resulting in the
    execution of arbitrary code in the context of the user.
    (CVE-2016-0025, CVE-2016-3233)

  - An flaw exists due to improper disclosure of memory
    contents. An unauthenticated, remote attacker can
    exploit this by convincing a user to open a specially
    crafted file, resulting in the disclosure of potentially
    sensitive information. (CVE-2016-3234)

  - A flaw exists due to improper validation of input
    before loading OLE library files. A local attacker can
    exploit this, via a specially crafted application, to
    execute arbitrary code. (CVE-2016-3235)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-070");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Word 2007, 2010, 2013, 2013
RT, and 2016; Microsoft Excel 2007 and 2010; Microsoft Visio 2007,
2010, 2013, and 2016; Visio Viewer 2007 and 2010; Word Viewer;
Microsoft Office Compatibility Pack; Office Web Apps 2010 and 2013;
Microsoft SharePoint Server 2010 and 2013; and Office Online Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Office OLE Multiple DLL Side Loading Vulnerabilities');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/06/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/15");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies(
    "office_installed.nasl",
    "microsoft_owa_installed.nbin",
    "microsoft_sharepoint_installed.nbin",
    "smb_hotfixes.nasl",
    "ms_bulletin_checks_possible.nasl"
  );
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

bulletin = 'MS16-070';
kbs = make_list(
  '2596915', # Visio 2007 SP3 Viewer
  '2999465', # Visio 2010 Viewer
  '3114740', # Visio 2007 SP3 
  '3114872', # Visio 2010 SP2
  '3115014', # Word Automation Services on SharePoint Server 2013
  '3115020', # Visio 2013 SP1
  '3115041', # Visio 2016 
  '3115107', # Excel 2007 SP3
  '3115111', # Office Compatibility Pack SP3
  '3115130', # Excel 2007 SP2
  '3115134', # Office Online Server
  '3115144', # Office 2016
  '3115170', # Office Web Apps 2013
  '3115173', # Word 2013 SP1
  '3115182', # Word 2016
  '3115187', # Word Viewer
  '3115194', # Microsoft Office Compatibility SP3
  '3115195', # Word 2007 SP3
  '3115196', # Word Automation Services on SharePoint Server 2010
  '3115198', # Office 2010 SP2
  '3115243', # Word 2010 SP2
  '3115244'  # Office Web Apps 2010
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();

global_var office_online_server_path;

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
office_online_server_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office16.WacServer\InstallLocation"
);

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

vuln = FALSE;

function perform_office_online_server_checks()
{
  local_var path;
  if(office_online_server_path)
  {
    path = hotfix_append_path(path:office_online_server_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.7102.2226", min_version:"16.0.6000.0", path:path, bulletin:bulletin, kb:"3115134", product:"Office Online Server") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# Visio Checks
######################################################################
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
    # Visio Viewer
    if ("12.0" >< version && hotfix_is_vulnerable(path:path, file:"vviewdwg.dll", version:"12.0.6749.5000", min_version:"12.0.6600.0", bulletin:bulletin, kb:"2596915"))
      vuln = TRUE;
    if ("14.0" >< version && hotfix_is_vulnerable(path:path, file:"vviewdwg.dll", version:"14.0.7170.5000", min_version:"14.0.6500.0", bulletin:bulletin, kb:"2999465"))
      vuln = TRUE;

    # Main Visio Executable Checks
    if ("12.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"12.0.6749.5000", min_version:"12.0.6600.0", bulletin:bulletin, kb:"3114740"))
      vuln = TRUE;
    if ("14.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.7170.5000", min_version:"14.0.6500.0", bulletin:bulletin, kb:"3114872"))
      vuln = TRUE;
    if ("15.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"15.0.4831.1000", min_version:"15.0.4000.0", bulletin:bulletin, kb:"3115020"))
      vuln = TRUE;
    if ("16.0" >< version && 
      (
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.4390.1000", channel:"MSI", channel_product:"Visio", bulletin:bulletin, kb:"3115041") ||
        # deferred 1
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.6001.1082", channel:"Deferred", channel_product:"Visio", bulletin:bulletin, kb:"3115041") ||
        # deferred 2
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.6741.2048", channel:"Deferred", channel_version:"1602", channel_product:"Visio", bulletin:bulletin, kb:"3115041") ||
        # first release for deferred
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.6965.2058", channel:"First Release for Deferred", channel_product:"Visio", bulletin:bulletin, kb:"3115041") ||
        # current
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.6965.2058", channel:"Current", channel_product:"Visio", bulletin:bulletin, kb:"3115041") 
      )
    ) vuln = TRUE;
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
      else if (owa_install['Product'] == "2013")
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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7170.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3115244", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"ExcelServicesEcs\bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4833.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3115170", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

function perform_office_checks()
{
  local_var office_vers, office_sp, path, excel_checks;
  office_vers = hotfix_check_office_version();

  # 2010
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7170.5000", path:path, bulletin:bulletin, kb:"3115198", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  # 2016
  if (office_vers['16.0'])
  {
    path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"16.0"), value:"Microsoft Office\root\Office16");
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && office_sp == 0)
    {
      if (
        hotfix_check_fversion(file:"mso.dll", version:"16.0.4390.1000", path:path, bulletin:bulletin, kb:"3115144", product:"Microsoft Office 2016") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6749.5000", "kb", "3115107"),
    "14.0", make_array("sp", 2, "version", "14.0.7170.5000", "kb", "3115130")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;
}

function perform_office_product_checks()
{
  local_var checks, word_vwr_checks, vwr_checks, compat_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Word Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6749.5000", "kb", "3115195"),
    "14.0", make_array("sp", 2, "version", "14.0.7170.5000", "kb", "3115243"),
    "15.0", make_array("sp", 1, "version", "15.0.4833.1000", "kb", "3115173"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4393.1000", "channel", "MSI", "kb", "3115182"),
      make_array("sp", 0, "version", "16.0.6001.1082", "channel", "Deferred", "kb", "3115182"),
      make_array("sp", 0, "version", "16.0.6741.2048", "channel", "Deferred", "channel_version", "1602", "kb", "3115182"),
      make_array("sp", 0, "version", "16.0.6965.2058", "channel", "First Release for Deferred", "kb", "3115182"),
      make_array("sp", 0, "version", "16.0.6965.2058", "channel", "Current", "kb", "3115182")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if(!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8429.0", "kb", "3115187")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;
  }

  ######################################################################
  # Word Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6749.5000", kb:"3115194", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6749.5000", "kb", "3115111")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:compat_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var installs, install, path, prod;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install["Product"] == "2010")
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
    }
  }

  # Office Services and Web Apps
  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7170.5000", path:path, bulletin:bulletin, kb:"3115196", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  if (sps_2013_path)
  {
    if (sps_2013_sp == "1")
    {
      if(sps_2013_edition == "Server")
      {
        path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
        if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4833.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3115014", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
          vuln = TRUE;
      }
    }
  }
}

perform_office_online_server_checks();
perform_office_checks();
perform_office_product_checks();
perform_sharepoint_checks();
perform_owa_checks();
perform_visio_checks();

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
