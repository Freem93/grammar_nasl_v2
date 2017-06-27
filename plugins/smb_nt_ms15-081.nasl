#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85350);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id(
    "CVE-2015-1642",
    "CVE-2015-2423",
    "CVE-2015-2466",
    "CVE-2015-2467",
    "CVE-2015-2468",
    "CVE-2015-2469",
    "CVE-2015-2470",
    "CVE-2015-2477"
  );
  script_bugtraq_id(
    76200,
    76202,
    76204,
    76206,
    76212,
    76214,
    76217,
    76219
  );
  script_osvdb_id(
    125961,
    125980,
    125981,
    125982,
    125983,
    125984,
    125985,
    125986
  );
  script_xref(name:"MSFT", value:"MS15-081");
  script_xref(name:"IAVA", value:"2015-A-0194");

  script_name(english:"MS15-081: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3080790)");
  script_summary(english:"Checks the Office, SharePoint, and OWA versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Word, Word
Viewer, Excel, PowerPoint, Visio, SharePoint Server, Microsoft Office
Compatibility Pack, Microsoft Word Web Apps, or Microsoft Office Web
Apps installed that is affected by multiple remote code execution
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted Office file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-1642,
    CVE-2015-2467, CVE-2015-2468, CVE-2015-2469,
    CVE-2015-2477)

  - An information disclosure vulnerability exists when
    files at a medium integrity level become accessible to
    Internet Explorer running in Enhanced Protection Mode
    (EPM). An attacker can exploit this vulnerability by
    leveraging another vulnerability to execute code in IE
    with EPM, and then executing Excel, Notepad, PowerPoint,
    Visio, or Word using an unsafe command line parameter.
    (CVE-2015-2423)

  - A remote code execution vulnerability exists due a
    failure to properly validate templates. A remote
    attacker can exploit this vulnerability by convincing a
    user to open a specially crafted template file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-2466)

  - A remote code execution vulnerability exists when Office
    decreases an integer value beyond its intended minimum
    value. A remote attacker can exploit this vulnerability
    by convincing a user to open a specially crafted Office
    file, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2015-2470)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-081");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, 2016, SharePoint Server 2010, SharePoint Server 2013, 
Microsoft Office Compatibility Pack, Microsoft Word Web Apps 2010, and
Microsoft Office Web Apps 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin" ,"microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS15-081';
kbs = make_list(
  2553313, # Office 2010 SP2 #
  2596650, # Office 2007 SP3 #
  2598244, # Office 2010 SP2 #
  2687409, # Office 2007 SP3 #
  2837610, # Office 2007 SP3 #
  2920691, # Word 2016
  2920708, # Visio 2016
  2965280, # Visio 2007 SP3 #
  2965310, # Office 2010 SP2 SP2 #
  2986254, # Office Compatibility Pack
  3039734, # 2013 SP1 / 2013 RT #
  3039798, # 2013 SP1 / 2013 RT #
  3054816, # 2013 SP1 / 2013 RT #
  3054858, # SharePoint 2013 Word Automation Services SP1 #
  3054876, # Visio 2010 SP2 #
  3054888, # Office 2007 SP3 #
  3054929, # Visio 2013 SP1 
  3054960, # SharePoint 2010 Word Automation Services SP2 #
  3054974, # Word Web Apps 2010 SP2 #
  3054991, # Excel 2013 SP1 #
  3054992, # Excel 2007 SP3 #
  3055003, # Word Web Apps 2013 SP1 #
  3055029, # PowerPoint 2013 SP1 #
  3055030, # Word 2013 SP1 #
  3055033, # PowerPoint 2010 SP2 #
  3055037, # Office 2010 SP2 #
  3055039, # Word 2010 SP2 #
  3055044, # Excel 2010 SP2 #
  3055051, # Power Point 2007 SP3 #
  3055052, # Word 2007 SP3 #
  3055053, # Word Viewer 
  3055054, # Word Viewer
  3085538  # Office 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2013_path, sps_2010_sp, sps_2013_sp, sps_2010_edition, sps_2013_edition;
  local_var installs, install, sp, path;

  # Get installs of SharePoint
  sps_2010_path = NULL;
  sps_2013_path = NULL;
  sp = NULL;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install['Product'] == "2010")
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

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Service
  # KB: 3054960  File: sword.dll Fix Ver: 14.0.7155.5000
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7155.5000", path:path, bulletin:bulletin, kb:"3054960", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013 SP1 - Word Automation Services
  # KB: 3054858 File: sword.dll Fix Ver: 15.0.4745.1000
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4745.1000", path:path, bulletin:bulletin, kb:"3054858", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
    
  }
}

######################################################################
# Office Web Apps
######################################################################
function perform_owa_checks()
{
  local_var owa_installs, owa_install, owa_2010_path, owa_2010_sp, owa_2013_path, owa_2013_sp;
  local_var path;
  # Get installs of Office Web Apps
  owa_installs = get_installs(app_name:"Microsoft Office Web Apps");
  if (!empty_or_null(owa_installs))
  {
    foreach owa_install (owa_installs[1])
    {
      if (owa_install['Product'] == "2010")
      {
        owa_2010_path = owa_install['path'];
        owa_2010_sp = owa_install['SP'];
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
  # KB: 3054974 File: sword.dll Fix Ver: 14.0.7155.5000
  ######################################################################
  if (owa_2010_path && owa_2013_sp == "2")
  {
    path = hotfix_append_path(path:owa_2010_path, value:"WordConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7155.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3054974", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  # KB: 3055003 File: sword.dll Fix Ver: 15.0.4745.1000
  ######################################################################
  if (owa_2013_path && owa_2013_sp == "1")
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4745.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3055003", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

# Generic Office Checks
function perform_office_checks()
{
  local_var office_vers, office_sp, path;
  office_vers = hotfix_check_office_version();
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"Microsoft Shared\Office12");
      if (
        hotfix_check_fversion(file:"vbe6.dll",      version: "6.5.10.55"      , path:path, bulletin:bulletin, kb:"2687409", product:"Microsoft Office 2007 SP3") == HCF_OLDER ||
        hotfix_check_fversion(file:"ieawsdc.dll",   version: "12.0.6035.0"    , path:path, bulletin:bulletin, kb:"2596650", product:"Microsoft Office 2007 SP3") == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll",       version: "12.0.6728.5000" , path:path, bulletin:bulletin, kb:"3054888", product:"Microsoft Office 2007 SP3") == HCF_OLDER ||
        hotfix_check_fversion(file:"msptls.dll",    version: "12.0.6727.5000" , path:path, bulletin:bulletin, kb:"2837610", product:"Microsoft Office 2007 SP3") == HCF_OLDER ||
        # This can't go in the generic checks because we must check ppcore.dll
        hotfix_check_fversion(file:"ppcore.dll",    version: "12.0.6727.5000" , path:path, bulletin:bulletin, kb:"3055051", product:"PowerPoint 2007 SP3"      ) == HCF_OLDER
      )
        vuln = TRUE;
    }

  }

  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"vbe7.dll",     version: "7.00.1637"     , path:path, bulletin:bulletin, kb:"2965310", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"ieawsdc.dll",  version: "14.0.6101.0"   , path:path, bulletin:bulletin, kb:"2553313", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"msptls.dll",   version: "14.0.7155.5000", path:path, bulletin:bulletin, kb:"2598244", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7155.5001", path:path, bulletin:bulletin, kb:"3055037", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && int(office_sp) == 1)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"15.0"), value:"Microsoft Office\Office15");
      if (
        hotfix_check_fversion(file:"vbe7.dll",      version: "7.01.1049"      , path:path, bulletin:bulletin, kb:"3039734", product:"Microsoft Office 2013 SP1") == HCF_OLDER ||
        hotfix_check_fversion(file:"ieawsdc.dll",   version: "15.0.4421.0"    , path:path, bulletin:bulletin, kb:"3039798", product:"Microsoft Office 2013 SP1") == HCF_OLDER ||
        hotfix_check_fversion(file:"msptls.dll",    version: "15.0.4745.1000" , path:path, bulletin:bulletin, kb:"3054816", product:"Microsoft Office 2013 SP1") == HCF_OLDER
      ) 
        vuln = TRUE;
    }
  }
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && int(office_sp) == 0)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"16.0"), value:"Microsoft Office\root\Office16");
      if (
        hotfix_check_fversion(file:"ieawsdc.dll", version:"15.0.4421.0", channel:"MSI", path:path, bulletin:bulletin, kb:"3085538", product:"Microsoft Office 2016") == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var excel_checks, word_checks, ppt_checks, word_vwr_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6727.5000", "kb", "3054992"),
    "14.0", make_array("sp", 2, "version", "14.0.7155.5000", "kb", "3055044"),
    "15.0", make_array("sp", 1, "version", "15.0.4745.1000", "kb", "3054991")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint
  ######################################################################
  ppt_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7155.5000", "kb", "3055033"),
    "15.0", make_array("sp", 1, "version", "15.0.4745.1000", "kb", "3055029")
  );
  if (hotfix_check_office_product(product:"PowerPoint", checks:ppt_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6727.5000", "kb", "3055052"),
    "14.0", make_array("sp", 2, "version", "14.0.7155.5001", "kb", "3055039"),
    "15.0", make_array("sp", 1, "version", "15.0.4745.1001", "kb", "3055030"),
    "16.0", make_array("sp", 0, "version", "16.0.4288.1000", "channel", "MSI", "kb", "2920691")
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if(!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8420.0", "kb", "3055053")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;

    foreach install (keys(installs))
    {
      path = installs[install];
      if(hotfix_check_fversion(file:"mso.dll", version: "11.0.8420.0", min_version:"11.0.0.0", path:path, bulletin:bulletin, kb:"3055054", product:"Microsoft Word Viewer") == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ######################################################################
  # Word Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll", version:"12.0.6727.5000", kb: "2986254", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
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

  # Exe checks
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Visio/' - '/VisioPath';
    if ("16.0" >!< version && "15.0" >!< version && "14.0" >!< version && "12.0" >!< version)
      continue;
    path = installs[install];
    if ("16.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.4288.1000", channel:"MSI", channel_product:"Visio", bulletin:bulletin, kb:"2920708"))
      vuln = TRUE;
    if ("15.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"15.0.4745.1000", min_version:"15.0.4000.0", bulletin:bulletin, kb:"3054929"))
      vuln = TRUE;
    if ("14.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.7155.5000", min_version:"14.0.6500.0", bulletin:bulletin, kb:"3054876"))
      vuln = TRUE;
    if ("12.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"12.0.6727.5000", min_version:"12.0.6000.0", bulletin:bulletin, kb:"2965280"))
      vuln = TRUE;
  }
}

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
