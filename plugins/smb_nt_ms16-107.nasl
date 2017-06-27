#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93481);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2016-0137",
    "CVE-2016-0141",
    "CVE-2016-3357",
    "CVE-2016-3358",
    "CVE-2016-3359",
    "CVE-2016-3360",
    "CVE-2016-3361",
    "CVE-2016-3362",
    "CVE-2016-3363",
    "CVE-2016-3364",
    "CVE-2016-3365",
    "CVE-2016-3366",
    "CVE-2016-3381"
  );
  script_bugtraq_id(
    92785,
    92786,
    92791,
    92795,
    92796,
    92798,
    92799,
    92801,
    92803,
    92804,
    92805,
    92831,
    92903
  );
  script_osvdb_id(
    144166,
    144167,
    144168,
    144169,
    144170,
    144171,
    144172,
    144173,
    144174,
    144175,
    144176,
    144177,
    144178
  );
  script_xref(name:"MSFT", value:"MS16-107");
  script_xref(name:"IAVA", value:"2016-A-0243");

  script_name(english:"MS16-107: Security Update for Microsoft Office (3185852)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application installed on the remote Windows host
is missing a security update. It is, therefore, affected by multiple
vulnerabilities :

  - An information disclosure vulnerability exists in the
    the Click-to-Run (C2R) components due to improper
    handling of objects in memory. An authenticated, remote
    attacker can exploit this, via a specially crafted
    application, to obtain sensitive information and thereby
    bypass the Address Space Layout Randomization (ASLR)
    security feature. (CVE-2016-0137)

  - An information disclosure vulnerability exists due to
    Visual Basic macros improperly exporting a user's private
    key from the certificate store while saving a document.
    An unauthenticated, remote attacker can exploit this,
    by convincing a user to provide the saved document, to
    gain access to the user's private key. (CVE-2016-0141)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office software due to improper handling of
    objects in memory. A remote attacker can exploit these,
    by convincing a user to open a specially crafted Office
    file, to execute arbitrary code in the context of the
    current user. (CVE-2016-3357, CVE-2016-3358,
    CVE-2016-3359, CVE-2016-3360, CVE-2016-3361,
    CVE-2016-3362, CVE-2016-3363, CVE-2016-3364,
    CVE-2016-3365, CVE-2016-3381)

  - A spoofing vulnerability exists in Microsoft Outlook due
    to a failure to conform to RFC2046 and properly identify
    the end of a MIME attachment. An unauthenticated, remote
    attacker can exploit this, by convincing a user to open
    a specially crafted email attachment, to cause antivirus
    or antispam security features to fail. (CVE-2016-3366)");
   script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-107");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Excel 2007, 2010, 2013, 2013
RT, and 2016; Microsoft PowerPoint 2007, 2010, 2013, and 2013 RT;
Microsoft Outlook 2007, 2010, 2013, 2013 RT, and 2016; Microsoft Visio
2016; Office Compatibility Pack; Excel Viewer; PowerPoint Viewer; Word
Viewer; Microsoft SharePoint Server 2007, 2010, and 2013; Office Web
Apps 2010 and 2013; and Office Online Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
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

bulletin = 'MS16-107';
kbs = make_list(
  '2553432', # Office 2010 SP2 #
  '2597974', # PowerPoint Compatibility Pack SP3 #
  '3054862', # SharePoint Server 2013 SP1 #
  '3054969', # PowerPoint Viewer #
  '3114744', # PowerPoint 2007 SP3 #
  '3115112', # SharePoint Excel Services 2007 SP3 #
  '3115119', # SharePoint Excel Services 2010 SP2
  '3115169', # SharePoint Excel Automation Services 2013 SP1 #
  '3115443', # SharePoint Word Automation Services 2013 SP1 #
  '3115459', # Excel 2007 SP3 #
  '3115462', # Office Compatability Pack SP3 #
  '3115463', # Excel Viewer #
  '3115466', # SharePoint Word Automation Services 2010 SP2 #
  '3115467', # PowerPoint 2010 SP2 #
  '3115472', # Office Web Apps 2010 SP2 #
  '3115487', # PowerPoint 2013 SP1 #
  '3118268', # Office 2013 SP1 #
  '3118270', # Office Web Apps 2013 SP1 #
  '3118280', # Outlook 2013 SP1 #
  '3118284', # Excel 2013 SP1 #
  '3118290', # Excel 2016 #
  '3118292', # Office 2016 #
  '3118293', # Outlook 2016 #
  '3118297', # Word Viewer #
  '3118299', # Office Online Server #
  '3118300', # Office 2007 SP3 #
  '3118303', # Outlook 2007 SP3 #
  '3118309', # Office 2010 SP2 #
  '3118313', # Outlook 2010 SP3 #
  '3118316'  # Excel 2010 SP2 #
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
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.7323.2225", min_version:"16.0.6000.0", path:path, bulletin:bulletin, kb:"3118299", product:"Office Online Server") == HCF_OLDER)
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
    if (hotfix_check_fversion(file:"msoserver.dll", version:"14.0.7173.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3115472", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4859.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3118270", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2007_path, sps_2007_sp, sps_2007_edition;
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var installs, install, path, commonfiles;

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
    }
  }

  commonfiles = hotfix_get_commonfilesdir();
  if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

  ######################################################################
  # SharePoint Server 2013 SP1 - Word Automation Services
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4859.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3115169", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
    vuln = TRUE;

    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4859.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3115443", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;

    if (hotfix_check_fversion(file:"ppserver.dll", version:"15.0.4859.1000", path:path, bulletin:bulletin, kb:"3054862", product:"Office SharePoint Server 2013") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2007 SP3 - Excel Services
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6755.5000", path:path, bulletin:bulletin, kb:"3115112", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"msoserver.dll", version:"14.0.7173.5000", path:path, bulletin:bulletin, kb:"3115466", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7173.5000", path:path, bulletin:bulletin, kb:"3115119", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }
}
 
function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, kb;
  office_vers = hotfix_check_office_version();

  ######################################################################
  # Office 2007 Checks
  ######################################################################
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      prod = "Microsoft Office 2007 SP3";
      common_path = hotfix_get_officecommonfilesdir(officever:"12.0");

      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6755.5000" , path:path, bulletin:bulletin, kb:"3118300", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"12.0"), value:"Microsoft Office\Office12");
      if (hotfix_check_fversion(file:"outlmime.dll", version: "12.0.6755.5000" , path:path, bulletin:bulletin, kb:"3118303", product:"Outlook 2007 SP3") == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"ppcore.dll", version: "12.0.6755.5000" , path:path, bulletin:bulletin, kb:"3114744", product:"PowerPoint 2007 SP3") == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ######################################################################
  # Office 2010 Checks
  ######################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");

      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office14");
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7173.5000", path:path, bulletin:bulletin, kb:"3118309", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (hotfix_check_fversion(file:"offowc.dll", version:"14.0.7173.5000", path:path, bulletin:bulletin, kb:"2553432", product:prod) == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"outlmime.dll", version: "14.0.7173.5000" , path:path, bulletin:bulletin, kb:"3118313", product:"Outlook 2010 SP2") == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"ppcore.dll", version: "14.0.7173.5000" , path:path, bulletin:bulletin, kb:"3115467", product:"PowerPoint 2010 SP2") == HCF_OLDER)
        vuln = TRUE;

      if ( "64" >< get_kb_item("SMB/Office/14.0/Bitness"))
      {
        path = hotfix_append_path(path:hotfix_get_commonfilesdirx86(), value:"Microsoft Shared\Office14");
        if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7173.5000", path:path, bulletin:bulletin, kb:"3118309", product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    }
  }

  ######################################################################
  # Office 2013 Checks
  ######################################################################
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && int(office_sp) == 1)
    {
      prod = "Microsoft Office 2013 SP1";
      common_path = hotfix_get_officecommonfilesdir(officever:"15.0");

      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office15");
      if (hotfix_check_fversion(file:"mso.dll", version: "15.0.4859.1000", path:path, bulletin:bulletin, kb:"3118268", product:prod) == HCF_OLDER)
        vuln = TRUE;

      if ( "64" >< get_kb_item("SMB/Office/15.0/Bitness"))
      {
        path = hotfix_append_path(path:hotfix_get_commonfilesdirx86(), value:"Microsoft Shared\Office15");
        if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4859.1000", path:path, bulletin:bulletin, kb:"3118268", product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    }
  }

  ######################################################################
  # Office 2016 Checks
  ######################################################################
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && int(office_sp) == 0)
    {
      prod = "Microsoft Office 2016";
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"16.0"), value:"Microsoft Shared\Office16");
      if (
        hotfix_check_fversion(file:"mso.dll", version:"16.0.4432.1000", channel:"MSI", channel_product:"Office", path:path, bulletin:bulletin, kb:"3118292", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll", version:"16.0.6701.1041", channel:"Deferred", channel_version:"1602", channel_product:"Office", path:path, bulletin:bulletin, kb:"3118292", product:prod) == HCF_OLDER #||
##TODO
 #       hotfix_check_fversion(file:"mso.dll", version:"16.0.7127.1019", channel:"Current", channel_product:"Office", path:path, bulletin:bulletin, kb:"3118292", product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      if ( "64" >< get_kb_item("SMB/Office/16.0/Bitness"))
      {
        path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"16.0"), value:"Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\OFFICE16");
        if (
          hotfix_check_fversion(file:"mso.dll", version:"16.0.4432.1000", channel:"MSI", channel_product:"Office", path:path, bulletin:bulletin, kb:"3118292", product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:"mso.dll", version:"16.0.6701.1041",  channel:"Deferred", channel_version:"1602", channel_product:"Office", path:path, bulletin:bulletin, kb:"3118292", product:prod) == HCF_OLDER #||
##TODO
 #         hotfix_check_fversion(file:"mso.dll", version:"16.0.7127.1019", channel:"Current", channel_product:"Office", path:path, bulletin:bulletin, kb:"3118292", product:prod) == HCF_OLDER
        )
          vuln = TRUE;
      }
    }
  }
}

function perform_office_product_checks()
{
  local_var excel_checks, word_checks, onenote_checks, outlook_checks, ppt_vwr_checks, excel_compat_checks,excel_vwr_checks,powerpoint_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6755.5000", "kb", "3115459"),
    "14.0", make_array("sp", 2, "version", "14.0.7173.5000", "kb", "3118316"),
    "15.0", make_array("sp", 1, "version", "15.0.4859.1000", "kb", "3118284"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4432.1003", "channel", "MSI", "kb", "3118290"),
      make_array("sp", 0, "version", "16.0.6001.1090", "channel", "Deferred", "kb", "3118290"),
      make_array("sp", 0, "version", "16.0.6741.2071", "channel", "Deferred", "channel_version", "1602", "kb", "3118290"),
      make_array("sp", 0, "version", "16.0.6965.2084", "channel", "First Release for Deferred", "kb", "3118290"),
      make_array("sp", 0, "version", "16.0.7070.2058", "channel", "Current", "kb", "3118290")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Outlook Checks
  ######################################################################
  outlook_checks = make_array(
    "15.0", make_array("sp", 1, "version", "15.0.4859.1000", "kb", "3118280"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4432.1001", "channel", "MSI", "kb", "3118293"),
      make_array("sp", 0, "version", "16.0.6001.1090", "channel", "Deferred", "kb", "3118290"),
      make_array("sp", 0, "version", "16.0.6741.2071", "channel", "Deferred", "channel_version", "1602", "kb", "3118290"),
      make_array("sp", 0, "version", "16.0.6965.2084", "channel", "First Release for Deferred", "kb", "3118290"),
      make_array("sp", 0, "version", "16.0.7070.2058", "channel", "Current", "kb", "3118290")
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:outlook_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  excel_vwr_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6755.5000", "kb", "3115463")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if (!isnull(installs))
  {
    foreach install (keys(installs))
    {
      path = installs[install];
      path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
      if(hotfix_check_fversion(path:path, file:"mso.dll", version:"11.0.8434.0", kb:"3118297", bulletin:bulletin, min_version:"11.0.0.0", product:"Microsoft Word Viewer") == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ######################################################################
  # PowerPoint Checks
  ######################################################################
  powerpoint_checks = make_array(
    "15.0", make_array("sp", 1, "version", "15.0.4859.1000", "kb", "3115487")
  );
  if (hotfix_check_office_product(product:"PowerPoint", checks:powerpoint_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint Viewer 2010
  ######################################################################
  ppt_vwr_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7173.5000", "kb", "3054969")
  );
  if (hotfix_check_office_product(product:"PowerPointViewer", display_name:"PowerPoint Viewer", checks:ppt_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  excel_compat_checks = make_array(
    "12.0", make_array("version", "12.0.6755.5000", "kb", "3115462")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:excel_compat_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/PowerPointCnv/*/ProductPath");
  if (!isnull(installs))
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"ppcnv.dll", version:"12.0.6755.5000", kb:"2597974", bulletin:bulletin, min_version:"12.0.0.0", product:"PowerPoint Compatability Pack SP3") == HCF_OLDER)
      vuln = TRUE;
  }
}

perform_office_checks();
perform_office_product_checks();
perform_office_online_server_checks();
perform_owa_checks();
perform_sharepoint_checks();

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
