#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83416);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2015-1682", "CVE-2015-1683");
  script_bugtraq_id(74481, 74484);
  script_osvdb_id(122005, 122006);
  script_xref(name:"MSFT", value:"MS15-046");
  script_xref(name:"IAVA", value:"2015-A-0103");

  script_name(english:"MS15-046: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3057181)");
  script_summary(english:"Checks the Office, SharePoint, and OWA versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Microsoft
Word, Microsoft Excel, Microsoft PowerPoint, SharePoint Server,
SharePoint Foundation Server, or Microsoft Office Web Apps installed
that is affected by multiple remote code execution vulnerabilities due
to improper handling of objects in memory. A remote attacker can
exploit these vulnerabilities by convincing a user to open a specially
crafted file, resulting in execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-046");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, Office 2010,
Office 2013, Word 2010, Word 2013, Excel 2010, Excel 2013, PowerPoint
2010, PowerPoint 2013, PowerPoint Viewer, SharePoint Server Foundation
2010, SharePoint Server 2013, and Office Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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
include("datetime.inc");

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-046';
kbs = make_list(
  2975808, # Office 2013 SP1
  2986216, # Excel 2013 SP1
  2975816, # PowerPoint 2013 SP1
  2965307, # Word 2013 SP1
  3023055, # SharePoint 2013 Word Automation Services SP1
  3039725, # SharePoint 2013 Excel Automation Services SP1
  3039748, # Office Web Apps 2013 SP1
  3039736, # SharePoint Server 2013 SP1
  3054833, # SharePoint 2010 Word Automation Services SP2 replaces 2965233
  3054834, # Office 2010 SP2 replaces 2999412
  3054835, # PowerPoint 2010 SP2 replaces 2999420
  3054838, # Excel Web Apps 2010 SP2 replaces 2956193
  3054839, # SharePoint 2010 Excel Automation Services SP2 replaces 2956194
  3054840, # PowerPoint Viewer replaces 2956195
  3054841, # Office 2010 SP2 replaces 2965311
  3054842, # Word 2010 SP2 replaces 2965237
  3054843, # Office Web Apps 2010 SP2 replaces 2956140
  3054845, # Excel 2010 SP2 replaces 2965240
  3054847, # SharePoint Server 2010 SP2 replaces 3017815
  3054848, # Office 2010 SP2 replaces 2965242
  3085544  # Offcie 2007 SP3 replaces 2965282
);

######################################################################
# Main
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();

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
      if (hotfix_check_fversion(file:"Mso.dll", version:"12.0.6734.5000", path:path, bulletin:bulletin, kb:"3085544", product:"Microsoft Office 2007 SP3") == HCF_OLDER)
        vuln = TRUE;
    }
  }
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (hotfix_check_fversion(file:"Wwlib.dll", version:"14.0.7151.5001", path:path, bulletin:bulletin, kb:"3054841", product:"Microsoft Office 2010") == HCF_OLDER)
        vuln = TRUE;
      if (hotfix_check_fversion(file:"Oart.dll", version:"14.0.7151.5001", path:path, bulletin:bulletin, kb:"3054834", product:"Microsoft Office 2010") == HCF_OLDER)
        vuln = TRUE;
      if (hotfix_check_fversion(file:"Oartconv.dll", version:"14.0.7151.5001", path:path, bulletin:bulletin, kb:"3054848", product:"Microsoft Office 2010") == HCF_OLDER)
        vuln = TRUE;
    }
  }
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && int(office_sp) <= 1)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"15.0"), value:"Microsoft Office\Office15");
      if (hotfix_check_fversion(file:"Oart.dll", version:"15.0.4719.1000", path:path, bulletin:bulletin, kb:"2975808", product:"Microsoft Office 2013") == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var excel_checks, ppt_checks, word_checks, ppt_vwr_checks;

  ######################################################################
  # Excel
  ######################################################################
  excel_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7151.5001", "kb", "3054845"),
    "15.0", make_array("sp", 1, "version", "15.0.4719.1000", "kb", "2986216")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint
  ######################################################################
  ppt_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7151.5001", "kb", "3054835"),
    "15.0", make_array("sp", 1, "version", "15.0.4719.1000", "kb", "2975816")
  );
  if (hotfix_check_office_product(product:"PowerPoint", checks:ppt_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word
  ######################################################################
  word_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7151.5001", "kb", "3054842"),
    "15.0", make_array("sp", 1, "version", "15.0.4719.1000", "kb", "2965307")
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint Viewer 2010
  # KB: 2956195 Fix Ver: 14.0.7149.5000
  ######################################################################
  ppt_vwr_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7151.5001", "kb", "3054840")
  );
  if (hotfix_check_office_product(product:"PowerPointViewer", display_name:"PowerPoint Viewer", checks:ppt_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2013_path, sps_2010_sp, sps_2013_sp, sps_2010_edition, sps_2013_edition;
  local_var installs, install, sp, path;
  local_var share, name, port, login, pass, domain, rc;
  local_var file, timestamp, file_timestamp, kb, info;

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
  # KB: 3054833  File: sword.dll Fix Ver: 14.0.7151.5001
  # SharePoint Server 2010 SP2 - Excel Services
  # KB: 3054839 File: xlsrv.dll Fix Ver: 14.0.7151.5001
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7151.5001", path:path, bulletin:bulletin, kb:"3054833", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7151.5001", path:path, bulletin:bulletin, kb:"3054839", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Foundation 2010 SP2
  # KB: 3054847 File: Onetutil.dll Fix Ver: 14.0.7151.5001
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Foundation")
  {
    NetUseDel(close:FALSE);

    share = hotfix_path2share(path:windir);
    name   = kb_smb_name();
    port   = kb_smb_transport();
    login  = kb_smb_login();
    pass   = kb_smb_password();
    domain = kb_smb_domain();

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc == 1)
    {
      path = hotfix_append_path(path:sps_2010_path, value:"TEMPLATE\LAYOUTS\entityeditor.debug.js");

      file_timestamp = hotfix_get_timestamp(path:path);

      hotfix_handle_error(error_code:file_timestamp['error'],
                    file:path,
                    appname:"SharePoint Foundation 2010 SP2",
                    exit_on_fail:false);

      timestamp = file_timestamp['value'];

      NetUseDel(close:FALSE);

      if (!isnull(timestamp))
      {
        if(timestamp < 1431493088)
        {
          vuln = TRUE;
          kb = "3054847";
          info =
            '\n  Product             : Sharepoint Foundation 2010 SP2\n' +
            '\n  File                : ' + path +
            '\n  Installed timestamp : ' + strftime(timestamp) +
            '\n  Fixed timestamp     : ' + strftime(1431493088) + '\n';
          hotfix_add_report(info, bulletin:bulletin, kb:kb);
        }
      }
    }
    NetUseDel(close:FALSE);
  }

  ######################################################################
  # SharePoint Server 2013 SP1 - Word Automation Services
  # KB: 3023055 File: sword.dll Fix Ver: 15.0.4719.1000
  # SharePoint Server 2013 SP1 - Excel Services
  # KB: 3039725 File: xlsrv.dll Fix Ver: 15.0.4719.1000
  # SharePoint Server 2013 SP1
  # KB: 3039736 File:Microsoft.Office.Server.PowerPoint.dll Fix Ver:15.0.4553.1000
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4719.1000", path:path, bulletin:bulletin, kb:"3023055", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
    path = hotfix_append_path(path:sps_2013_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4719.1000", path:path, bulletin:bulletin, kb:"3039725", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
      vuln = TRUE;
    path = hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Server.PowerPoint\v4.0_15.0.0.0__71e9bce111e9429c");
    if (hotfix_check_fversion(file:"Microsoft.Office.Server.PowerPoint.dll", version:"15.0.4553.1000", path:path, bulletin:bulletin, kb:"3039736", product:"Office SharePoint Server 2013") == HCF_OLDER)
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
  owa_installs = get_installs(app_name:"Office Web Apps");
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
  # KB: 2956140 File: sword.dll Fix Ver: 14.0.7149.5000
  # Excel Web Apps 2010 SP2
  # KB: 2956193 File: xlsrv.dll Fix Ver: 14.0.7149.5000
  ######################################################################
  if (owa_2010_path && owa_2013_sp == "2")
  {
    path = hotfix_append_path(path:owa_2010_path, value:"WordConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7151.5001", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3054843", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
    path = hotfix_append_path(path:owa_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7151.5001", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3054838", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  # KB: 3039748 File: sword.dll Fix Ver: 15.0.4719.1000
  ######################################################################
  if (owa_2013_path && owa_2013_sp == "1")
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4719.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3039748", product:"Office Web Apps 2013") == HCF_OLDER)
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
