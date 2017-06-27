#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85879);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2015-2520",
    "CVE-2015-2521",
    "CVE-2015-2522",
    "CVE-2015-2523",
    "CVE-2015-2545"
  );
  script_bugtraq_id(
    76561,
    76562,
    76564,
    76588,
    76667
  );
  script_osvdb_id(
    127212,
    127213,
    127214,
    127215,
    127216
  );
  script_xref(name:"MSFT", value:"MS15-099");
  script_xref(name:"IAVA", value:"2015-A-0214");
  script_xref(name:"EDB-ID", value:"38214");
  script_xref(name:"EDB-ID", value:"38215");
  script_xref(name:"EDB-ID", value:"38216");

  script_name(english:"MS15-099: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3089664)");
  script_summary(english:"Checks the Office and SharePoint versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Excel,
Excel Viewer, SharePoint Server, Microsoft Office Compatibility Pack,
Microsoft Office Web Apps, and/or Microsoft SharePoint Foundation
installed that is affected by one or more of the following
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted file in Microsoft
    Office, resulting in execution of arbitrary code in the
    context of the current user. (CVE-2015-2520,
    CVE-2015-2521, CVE-2015-2523)

  - A cross-site scripting vulnerability exists in
    SharePoint due to improper sanitization of user-supplied
    web requests. A remote attacker can exploit this
    vulnerability, via a specially crafted web request, to
    execute arbitrary script code in the context of the
    current user. (CVE-2015-2522)

  - A remote code execution vulnerability exists in
    Microsoft Office due to improper handling of malformed 
    graphics images. A remote attacker can exploit this
    vulnerability by convincing a user to open a file or
    visit a website containing a specially crafted EPS image
    binary, resulting in execution of arbitrary code in the
    context of the current user. (CVE-2015-2545)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-099");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, 2016, SharePoint Server 2013, Microsoft Office Compatibility
Pack, and Microsoft Office Web Apps 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS15-099';
kbs = make_list(
  3054813, # SharePoint Server 2013 SP1 #
  3054932, # Office 2013 SP1 #
  3054965, # Office 2010 SP2 #
  3054987, # Office 2007 SP3 #
  3085635, # Office 2016
  3054993, # Compat Pack 3 #
  3054995, # Excel viewer #
  3085483, # SharePoint Server 2013 SP1 #
  3085487, # Office Web Apps Server 2013 SP1
  3085501, # SharePoint Foundation 2013 SP1 #
  3085502, # Excel 2013 SP1 #
  3085526, # Excel 2010 SP2 #
  3085543, # Excel 2007 SP3 #
  2920693  # Excel 2016
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
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var installs, install, path, prod;

  sps_2013_path = NULL;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install['Product'] == "2013")
    {
      sps_2013_path = install['path'];
      sps_2013_sp = install['SP'];
      sps_2013_edition = install['Edition'];
      break;
    }
  }

  # Not found
  if(isnull(sps_2013_path))
    return;

  # Wrong SP
  if(isnull(sps_2013_sp) || sps_2013_sp != "1")
    return;

  if (sps_2013_edition == "Server")
  {
    prod = "SharePoint Server 2013";
    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (
        hotfix_check_fversion(file:"htmlutil.dll", version:"15.0.4753.1000", path:path, bulletin:bulletin, kb:"3054813", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"IGXServer.DLL", version:"15.0.4749.1000", path:path, bulletin:bulletin, kb:"3085483", product:prod) == HCF_OLDER
    )
      vuln = TRUE;
  }

  if (sps_2013_edition == "Foundation") {
    prod = "SharePoint Foundation 2013";
    path = hotfix_get_commonfilesdir();
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Web Server Extensions\15\BIN\");
    if (hotfix_check_fversion(file:"CsiSrv.dll", version:"15.0.4745.1000", path:path, bulletin:bulletin, kb:"3085501", product:prod) == HCF_OLDER) {
      set_kb_item(name:'www/0/XSS', value:TRUE);
      vuln = TRUE;
    }
  }
}

######################################################################
# Office Web Apps
######################################################################
function perform_owa_checks()
{
  local_var owa_installs, owa_install, owa_2013_path, owa_2013_sp;
  local_var path;
  # Get installs of Office Web Apps
  owa_installs = get_installs(app_name:"Microsoft Office Web Apps");
  if (!empty_or_null(owa_installs))
  {
    foreach owa_install (owa_installs[1])
    {
      if (owa_install['Product'] == "2013")
      {
        owa_2013_path = owa_install['path'];
        owa_2013_sp = owa_install['SP'];
        break;
      }
    }
  }

  # Not found
  if (isnull(owa_2013_path))
    return;

  # Wrong SP
  if (isnull(owa_2013_sp) || owa_2013_sp != "1")
    return;

  path = hotfix_append_path(path:owa_2013_path, value:"ExcelServicesEcs\bin");
  if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4753.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3085487", product:"Office Web Apps 2013") == HCF_OLDER)
    vuln = TRUE;
}

# Generic Office Checks
function perform_office_checks()
{
  local_var office_vers, office_sp, path, prod, kb;
  office_vers = hotfix_check_office_version();
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      prod = "Microsoft Office 2007 SP3";
      kb   = "3054987";
      path = hotfix_get_officecommonfilesdir(officever:"12.0");
      path = hotfix_append_path(path:path, value:"\Microsoft Shared\GRPHFLT");
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2006.1200.6736.5000", min_version:"2006.1200.0.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      kb   = "3054965";
      path = hotfix_get_officecommonfilesdir(officever:"14.0");
      path = hotfix_append_path(path:path, value:"\Microsoft Shared\GRPHFLT");
      if (
        hotfix_check_fversion(file:"epsimp32.flt", version:"2010.1400.4740.1000", min_version:"2010.1400.0.0",    path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"epsimp32.flt", version:"2010.1400.7162.5001", min_version:"2010.1200.6000.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && int(office_sp) == 1)
    {
      prod = "Microsoft Office 2013 SP1";
      kb   = "3054932";
      path = hotfix_get_officecommonfilesdir(officever:"15.0");
      path = hotfix_append_path(path:path, value:"\Microsoft Shared\GRPHFLT");
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2012.1500.4771.1002", min_version:"2012.1500.0.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && int(office_sp) == 0)
    {
      prod = "Microsoft Office 2016";
      kb   = "3085635";
      path = hotfix_get_officecommonfilesdir(officever:"16.0");
      path = hotfix_append_path(path:path, value:"\Microsoft Shared\GRPHFLT");
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2012.1600.4300.1002", min_version:"2012.1600.0.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

# Individual and odd ball office products
function perform_office_product_checks()
{
  local_var excel_checks, vwr_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6729.5000", "kb", "3085543"),
    "14.0", make_array("sp", 2, "version", "14.0.7157.5000", "kb", "3085526"),
    "15.0", make_array("sp", 1, "version", "15.0.4753.1000", "kb", "3085502"),
    "16.0", make_array("sp", 0, "version", "16.0.4288.1000", "channel", "MSI", "kb", "2920693")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
  if(!isnull(installs))
  {
    vwr_checks = make_array(
      "12.0", make_array("version", "12.0.6729.5000", "kb", "3054995")
    );
    if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:vwr_checks, bulletin:bulletin))
      vuln = TRUE;
  }

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(
      hotfix_check_fversion(path:path, file:"excelcnv.exe",  version:"12.0.6729.5000", kb: "3054993", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER ||
      hotfix_check_fversion(path:path, file:"excelconv.exe", version:"12.0.6729.5000", kb: "3054993", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER
    )
      vuln = TRUE;
  }
}

perform_office_checks();
perform_office_product_checks();
perform_sharepoint_checks();
perform_owa_checks();

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
