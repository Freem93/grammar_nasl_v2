#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88647);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/06 19:24:46 $");

  script_cve_id(
    "CVE-2016-0022",
    "CVE-2016-0039",
    "CVE-2016-0052",
    "CVE-2016-0053",
    "CVE-2016-0054",
    "CVE-2016-0055",
    "CVE-2016-0056"
  );
  script_bugtraq_id(
    82508,
    82512,
    82652,
    82654,
    82657,
    82660,
    82787
  );
  script_osvdb_id(
    134313,
    134314,
    134315,
    134316,
    134317,
    134318,
    134319
  );
  script_xref(name:"MSFT", value:"MS16-015");
  script_xref(name:"IAVA", value:"2016-A-0043");

  script_name(english:"MS16-015: Security Update for Microsoft Office to Address Remote Code Execution (3134226)");
  script_summary(english:"Checks file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Word, Word
Viewer, Excel, Excel Viewer, SharePoint, Microsoft Office
Compatibility Pack, or Office Web Apps installed that is affected by
multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted file in Microsoft
    Office, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2016-0022,
    CVE-2016-0052, CVE-2016-0053, CVE-2016-0054,
    CVE-2016-0055, CVE-2015-0056)

  - A cross-site scripting vulnerability exists in
    SharePoint due to improper sanitization of specially
    crafted web requests. An authenticated, remote attacker
    can exploit this, via a specially crafted web request,
    to execute arbitrary script code in a user's browser
    session. (CVE-2016-0039)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/ms16-015");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, and 2016; Word, Word Viewer, Excel, Excel Viewer; SharePoint
Server 2007, 2010, and 2013; SharePoint Foundation 2013, Microsoft
Office Compatibility Pack, and Office Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

bulletin = 'MS16-015';
kbs = make_list(
  '3039768', # SharePoint Server 2013 SP1
  '3114335', # Excel Services on SharePoint Server 2013 SP1
  '3114338', # Office Web Apps Server 2013 SP 1
  '3114401', # Excel Services on SharePoint Server 2010 SP2
  '3114407', # Office Web Apps 2010 SP2
  '3114432', # SharePoint Server 2007
  '3114481', # Word Automation Services on SharePoint Server 2013 SP1
  '3114548', # Word Compatibility Pack SP3
  '3114698', ### Excel 2016
  '3114702', ### Word 2016
  '3114724', # Word 2013 SP1
  '3114733', # SharePoint Foundation 2013 Server SP1
  '3114734', # Excel 2013 SP1
  '3114741', # Excel 2007 SP3
  '3114742', # Office 2007 SP3
  '3114745', # Excel Compatibility Pack SP3
  '3114747', # Excel Viewer
  '3114748', # Word 2007 SP3
  '3114752', # Ofice 2010 SP2
  '3114755', # Word 2010 SP2
  '3104759', # Excel 2010 SP2
  '3114773'  # Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();

vuln = FALSE;

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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7166.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3114407", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"ExcelServicesEcs\bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4797.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3114338", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

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
          hotfix_check_fversion(file:"mso.dll", version: "12.0.6743.5000" , path:path, bulletin:bulletin, kb:"3114742", product:"Microsoft Office 2007 SP3") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7166.5000", path:path, bulletin:bulletin, kb:"3114752", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      ) vuln = TRUE;

    }
  }
}

function perform_office_product_checks()
{
  local_var checks, word_vwr_checks, vwr_checks, compat_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6743.5000", "kb", "3114741"),
    "14.0", make_array("sp", 2, "version", "14.0.7166.5000", "kb", "3114759"),
    "15.0", make_array("sp", 1, "version", "15.0.4797.1000", "kb", "3114734"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4339.1000", "channel", "MSI", "kb", "3114698"),
      make_array("sp", 0, "version", "16.0.6001.1061", "channel", "First Release for Deferred", "kb", "3114698"),
      make_array("sp", 0, "version", "16.0.6366.2068", "channel", "Current", "kb", "3114698")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6743.5000", "kb", "3114748"),
    "14.0", make_array("sp", 2, "version", "14.0.7166.5000", "kb", "3114755"),
    "15.0", make_array("sp", 1, "version", "15.0.4797.1000", "kb", "3114724"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4339.1000", "channel", "MSI", "kb", "3114702"),
      make_array("sp", 0, "version", "16.0.6001.1061", "channel", "First Release for Deferred", "kb", "3114702"),
      make_array("sp", 0, "version", "16.0.6366.2068", "channel", "Current", "kb", "3114702")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6743.5000", "kb", "3114747")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if(!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8424.0", "kb", "3114773")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;
  }

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6743.5000", "kb", "3114745")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:compat_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6743.5000", kb: "3114548", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2007_path, sps_2007_sp, sps_2007_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
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
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6743.5000", path:path, bulletin:bulletin, kb:"3114432", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Excel Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7166.5000", path:path, bulletin:bulletin, kb:"3114401", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013
  ######################################################################
  # In this case the fix for SharePoint Server and SharePoint Foundation
  # are the same, this is not always the case
  if (sps_2013_path)
  {
    if (sps_2013_sp == "1")
    {
      if(sps_2013_edition == "Server")
      {
        path = hotfix_append_path(path:sps_2013_path, value:"Bin");
        if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4797.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3114335", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
         vuln = TRUE;

        path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
        if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4797.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3114481", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
        vuln = TRUE;

        path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
        if (hotfix_check_fversion(file:"msores.dll", version:"15.0.4769.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3039768", product:"SharePoint Server 2013 (wasrvloc)") == HCF_OLDER)
        vuln = TRUE;
      }

      prod = "SharePoint " + sps_2013_edition + " SP1";
      path = hotfix_append_path(path:hotfix_get_commonfilesdir(), value:"Microsoft Shared\Web Server Extensions\15\BIN\");
      if (hotfix_check_fversion(file:"onetutil.dll", version:"15.0.4797.1000", path:path, bulletin:bulletin, kb:"3114733", product:prod) == HCF_OLDER)
      {
        set_kb_item(name:"www/0/XSS", value:TRUE);
        vuln = TRUE;
      }
    }
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
