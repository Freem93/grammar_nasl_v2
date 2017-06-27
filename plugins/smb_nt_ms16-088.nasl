#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92019);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_cve_id(
    "CVE-2016-3278",
    "CVE-2016-3279",
    "CVE-2016-3280",
    "CVE-2016-3281",
    "CVE-2016-3282",
    "CVE-2016-3283",
    "CVE-2016-3284"
  );
  script_bugtraq_id(
    91574,
    91582,
    91587,
    91588,
    91589,
    91592,
    91592
  );
  script_osvdb_id(
    141405,
    141406,
    141407,
    141408,
    141409,
    141410,
    141411
  );
  script_xref(name:"MSFT", value:"MS16-088");
  script_xref(name:"IAVA", value:"2016-A-0176");

  script_name(english:"MS16-088: Security Update for Microsoft Office (3170008)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office software due to improper handling of
    objects in memory. A remote attacker can exploit these
    vulnerabilities by convincing a user to open a specially
    crafted Office file, resulting in the execution of
    arbitrary code in the context of the current user.
    (CVE-2016-3278, CVE-2016-3280, CVE-2016-3281,
    CVE-2016-3282, CVE-2016-3283, CVE-2016-3284)

  - A remote code execution vulnerability exists in
    Microsoft Office software due to improper handling of
    XLA files. A remote attacker can exploit this
    vulnerability by convincing a user to open a specially
    crafted XLA file in Office, resulting in the execution
    of arbitrary code in the context of the current user.
    (CVE-2016-3279)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-088");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Word 2007, 2010, 2013, 2013
RT, and 2016; Microsoft Excel 2007, 2010, 2013, 2013 RT, and 2016;
Microsoft Outlook 2010, 2013, 2013 RT, and 2016; Microsoft PowerPoint
2010, 2013, and 2013 RT; Excel Viewer; Word Viewer; Microsoft
Office Compatibility Pack; Office Web Apps 2010 and 2013; Microsoft
SharePoint Server 2010, 2013 and 2016; Microsoft SharePoint
Foundation 2010 and 2013; and Office Online Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/07/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS16-088';
kbs = make_list(
  '3114890', # SharePoint Foundation 2010 SP1
  '3115114', # Excel Viewer
  '3115118', # PowerPoint 2010 SP2
  '3115246', # Outlook 2010 SP2
  '3115254', # PowerPoint 2013 SP1
  '3115259', # Outlook 2013 SP1
  '3115262', # Excel 2013 SP1
  '3115272', # Excel 2016
  '3115279', # Outlook 2016
  '3115285', # Word Automation Services on SharePoint Server 2013 SP1
  '3115289', # Office Web Apps Server 2013 SP1
  '3115292', # Word 2013 SP1
  '3115294', # SharePoint Foundation 2013 SP1
  '3115299', # SharePoint Server 2016
  '3115301', # Word 2016
  '3115306', # Excel 2007 SP3
  '3115308', # Office Compatibility Pack SP3
  '3115309', # Office Compatibility Pack SP3
  '3115311', # Word 2007 SP3
  '3115312', # Word Automation Services on SharePoint Server 2010 SP2
  '3115315', # Office 2010 SP2
  '3115317', # Word 2010 SP2
  '3115318', # Office Web Apps 2010 SP2
  '3115322', # Excel 2010 SP2
  '3115386', # Office Online Server
  '3115393', # Word Viewer
  '3115395'  # Word Viewer
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
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.7124.2225", min_version:"16.0.6000.0", path:path, bulletin:bulletin, kb:"3115386", product:"Office Online Server") == HCF_OLDER)
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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7171.5002", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3115318", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4841.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3115289", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

function perform_office_checks()
{
  local_var office_vers, office_sp, path;
  office_vers = hotfix_check_office_version();

  # 2010
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7171.5002", path:path, bulletin:bulletin, kb:"3115315", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      ) vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var word_vwr_checks, excel_vwr_checks, excel_compat_checks;
  local_var excel_checks, word_checks, powerpoint_checks, outlook_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6750.5000", "kb", "3115306"),
    "14.0", make_array("sp", 2, "version", "14.0.7171.5000", "kb", "3115322"),
    "15.0", make_array("sp", 1, "version", "15.0.4841.1000", "kb", "3115262"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4405.1000", "channel", "MSI", "kb", "3115272"),
      make_array("sp", 0, "version", "16.0.6001.1085", "channel", "Deferred", "kb", "3115272"),
      make_array("sp", 0, "version", "16.0.6741.2056", "channel", "Deferred", "channel_version", "1602", "kb", "3115272"),
      make_array("sp", 0, "version", "16.0.6965.2066", "channel", "First Release for Deferred", "kb", "3115272"),
      make_array("sp", 0, "version", "16.0.7070.2026", "channel", "Current", "kb", "3115272")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Checks
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6752.5000", "kb", "3115311"),
    "14.0", make_array("sp", 2, "version", "14.0.7171.5002", "kb", "3115317"),
    "15.0", make_array("sp", 1, "version", "15.0.4841.1000", "kb", "3115292"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4405.1000", "channel", "MSI", "kb", "3115301"),
      make_array("sp", 0, "version", "16.0.6001.1085", "channel", "Deferred", "kb", "3115301"),
      make_array("sp", 0, "version", "16.0.6741.2056", "channel", "Deferred", "channel_version", "1602", "kb", "3115301"),
      make_array("sp", 0, "version", "16.0.6965.2066", "channel", "First Release for Deferred", "kb", "3115301"),
      make_array("sp", 0, "version", "16.0.7070.2026", "channel", "Current", "kb", "3115301")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint Checks
  ######################################################################
  powerpoint_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7171.5000", "kb", "3115118"),
    "15.0", make_array("sp", 1, "version", "15.0.4841.1000", "kb", "3115254")
  );
  if (hotfix_check_office_product(product:"PowerPoint", checks:powerpoint_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Outlook Checks
  ######################################################################
  outlook_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7169.5000", "kb", "3115246"),
    "15.0", make_array("sp", 1, "version", "15.0.4841.1000", "kb", "3115259"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4405.1000", "channel", "MSI", "kb", "3115279"),
      make_array("sp", 0, "version", "16.0.6001.1085", "channel", "Deferred", "kb", "3115279"),
      make_array("sp", 0, "version", "16.0.6741.2056", "channel", "Deferred", "channel_version", "1602", "kb", "3115279"),
      make_array("sp", 0, "version", "16.0.6965.2066", "channel", "First Release for Deferred", "kb", "3115279"),
      make_array("sp", 0, "version", "16.0.7070.2026", "channel", "Current", "kb", "3115279")
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:outlook_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  excel_vwr_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6750.5000", "kb", "3115114")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if (!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8431.0", "kb", "3115393")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;

    foreach install (keys(installs))
    {
      path = installs[install];
      path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
      if(hotfix_check_fversion(path:path, file:"mso.dll", version:"11.0.8430.0", kb:"3115395", bulletin:bulletin, min_version:"11.0.0.0", product:"Microsoft Word Viewer") == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ######################################################################
  # Word Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  if (!isnull(installs))
  {
    foreach install (keys(installs))
    {
      path = installs[install];
      path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
      if(hotfix_check_fversion(path:path, file:"wrd12cnv.dll", version:"12.0.6752.5000", kb:"3115309", bulletin:bulletin, min_version:"12.0.0.0", product:    "Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
    }
  }

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  excel_compat_checks = make_array(
    "12.0", make_array("version", "12.0.6750.5000", "kb", "3115308")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:excel_compat_checks, bulletin:bulletin))
    vuln = TRUE;

}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var sps_2016_path, sps_2016_sp, sps_2016_edition;
  local_var installs, install, path, commonfiles;

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
    else if (install['Product'] == "2016")
    {
      sps_2016_path = install['path'];
      sps_2016_sp = install['SP'];
      sps_2016_edition = install['Edition'];
    }
  }

  commonfiles = hotfix_get_commonfilesdir();
  if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7171.5002", path:path, bulletin:bulletin, kb:"3115312", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013 SP1 - Word Automation Services
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4841.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3115285", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2016
  ######################################################################
  if (sps_2016_path && sps_2016_sp == "0" && sps_2016_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2016_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.4405.1000", min_version:"16.0.0.0", path:path, bulletin:bulletin, kb:"3115299", product:"Office SharePoint Server 2016") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Foundation 2010 SP2
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Foundation")
  {
    if(commonfiles) path = hotfix_append_path(path:commonfiles, value:"Microsoft Shared\Web Server Extensions\14\BIN");
    else path = hotfix_append_path(path:sps_2010_path, value:"BIN");
    if (hotfix_check_fversion(file:"onetutil.dll", version:"14.0.7171.5000", min_version:"14.0.0.0", path:path, bulletin:bulletin, kb:"3114890", product:"Office SharePoint Foundation 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Foundation 2013 SP1
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Foundation")
  {
    if(commonfiles) path = hotfix_append_path(path:commonfiles, value:"Microsoft Shared\Web Server Extensions\15\BIN");
    else path = hotfix_append_path(path:sps_2013_path, value:"BIN");
    if (hotfix_check_fversion(file:"onetutil.dll", version:"15.0.4841.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3115294", product:"Office Sharepoint Foundation 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

perform_office_online_server_checks();
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
