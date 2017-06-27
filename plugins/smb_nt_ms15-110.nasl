#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86374);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/06 19:24:46 $");

  script_cve_id(
    "CVE-2015-2555",
    "CVE-2015-2556",
    "CVE-2015-2557",
    "CVE-2015-2558",
    "CVE-2015-6037",
    "CVE-2015-6039"
  );
  script_bugtraq_id(
    76988,
    76996,
    76997,
    77003,
    77009,
    77011
  );
  script_osvdb_id(
    128822,
    128823,
    128824,
    128825,
    128826,
    128827
  );
  script_xref(name:"MSFT", value:"MS15-110");

  script_name(english:"MS15-110: Security Updates for Microsoft Office to Address Remote Code Execution (3089440)");
  script_summary(english:"Checks the Office and SharePoint versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Excel,
Excel Viewer, SharePoint Server, Microsoft Office Compatibility Pack,
or Microsoft Office Web Apps installed that is affected by multiple
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted file, resulting in
    execution of arbitrary code in the context of the current
    user. (CVE-2015-2555, CVE-2015-2557, CVE-2015-2558)

  - An information disclosure vulnerability exists in the
    SharePoint InfoPath Forms Services due to improper
    parsing of document type definitions (DTD) in XML files.
    A remote attacker can exploit this, via a crafted XML
    file, to browse the contents of arbitrary files on a
    SharePoint server. (CVE-2015-2556)

  - An cross-site scripting vulnerability exists in Office
    Web Apps Server due to improper sanitization of crafted
    requests before returning it to the user. A remote
    attacker can exploit this to run arbitrary script code
    in the user's browser session. (CVE-2015-6037)

  - A security feature bypass vulnerability exists in
    SharePoint due to improper enforcement of permission
    levels for applications or users. This allows Office
    Marketplace to inject JavaScript code that will persist
    in a SharePoint page. A remote attacker can exploit this
    to conduct a cross-site scripting attack, resulting in
    execution of arbitrary code in the user's browser
    session. (CVE-2015-6039)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-110");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, 2016; SharePoint Server 2007, 2010, 2013; Microsoft Office
Compatibility Pack SP3; Microsoft Excel Viewer; and Microsoft Office
Web Apps 2010, 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
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

bulletin = 'MS15-110';
kbs = make_list(
  2553405, # SharePoint Server 2010
  2596670, # SharePoint Server 2007
  2920693, # Excel 2016
  3054994, # Excel Services for SharePoint Server 2007
  3085514, # Visio 2010 SP2
  3085520, # Office Web Apps 2010
  3085542, # Visio 2007 SP3
  3085567, # SharePoint Server 2013
  3085568, # Excel Services for SharePoint Server 2013
  3085571, # Office Web Apps 2013
  3085582, # SharePoint Foundation 2013
  3085583, # Excel 2013 SP1
  3085595, # Excel Web App 2010
  3085596, # Excel Services for SharePoint Server 2010
  3085609, # Excel 2010 SP2
  3085615, # Excel 2007 SP3
  3085618, # Compatibility Pack
  3085619  # Excel Viewer
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

  ######################################################################
  # SharePoint Server 2007 SP3
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"Microsoft.Office.InfoPath.Server.dll", version:"12.0.6732.5000", path:path, bulletin:bulletin, kb:"2596670", product:"Microsoft SharePoint Server 2007 SP3") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"Microsoft.Office.InfoPath.Server.dll", version:"14.0.7159.5000", path:path, bulletin:bulletin, kb:"2553405", product:"Microsoft SharePoint Server 2010 SP2") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013
  ######################################################################
  if (sps_2013_path)
  {
    if ("Server" >< sps_2013_edition && sps_2013_sp == "1")
    {
      prod = "SharePoint Server 2013 SP1";
      path = hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.SharePoint.Publishing\v4.0_15.0.0.0__71e9bce111e9429c");
      if (hotfix_check_fversion(file:"Microsoft.SharePoint.Publishing.dll", version:"15.0.4763.1000", path:path, bulletin:bulletin, kb:"3085567", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
    else if ("Foundation" >< sps_2013_edition && sps_2013_sp == "1")
    {
      prod = "SharePoint Foundation 2013 SP1";
      prod = "SharePoint Foundation 2013";
      path = hotfix_append_path(path:hotfix_get_commonfilesdir(), value:"Microsoft Shared\Web Server Extensions\15\BIN\");
      if (hotfix_check_fversion(file:"CsiSrv.dll", version:"15.0.4763.1000", path:path, bulletin:bulletin, kb:"3085582", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  # Office Services and Web Apps
  ######################################################################
  # SharePoint Server 2007 SP3 - Excel Services
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6732.5000", path:path, bulletin:bulletin, kb:"3054994", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Excel Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7159.5000", path:path, bulletin:bulletin, kb:"3085596", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013 SP1 - Excel Services
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4763.1000", path:path, bulletin:bulletin, kb:"3085568", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7160.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3085520", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7159.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3085595", product:"Excel Web App 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"ExcelServicesEcs\bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4763.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3085571", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

# Individual and odd ball office products
function perform_office_product_checks()
{
  local_var excel_checks, vwr_checks, compat_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6732.5000", "kb", "3085615"),
    "14.0", make_array("sp", 2, "version", "14.0.7160.5000", "kb", "3085609"),
    "15.0", make_array("sp", 1, "version", "15.0.4763.1000", "kb", "3085583"),
    "16.0", make_array("sp", 0, "version", "16.0.4288.1000", "channel", "MSI", "kb", "2920693")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6732.5000", "kb", "3085619")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6723.5000", "kb", "3085618")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:compat_checks, bulletin:bulletin))
    vuln = TRUE;
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
    if ("14.0" >!< version && "12.0" >!< version)
      continue;
    path = installs[install];
    if ("14.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.7160.5000", min_version:"14.0.6500.0", bulletin:bulletin, kb:"3085514"))
      vuln = TRUE;
    if ("12.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"12.0.6727.5000", min_version:"12.0.6000.0", bulletin:bulletin, kb:"3085542"))
      vuln = TRUE;
  }
}

perform_sharepoint_checks();
perform_owa_checks();
perform_office_product_checks();
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
