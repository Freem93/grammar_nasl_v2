#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97740);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id(
    "CVE-2017-0006",
    "CVE-2017-0019",
    "CVE-2017-0020",
    "CVE-2017-0027",
    "CVE-2017-0029",
    "CVE-2017-0030",
    "CVE-2017-0031",
    "CVE-2017-0052",
    "CVE-2017-0053",
    "CVE-2017-0105",
    "CVE-2017-0107"
  );
  script_bugtraq_id(
    96042,
    96043,
    96045,
    96050,
    96051,
    96052,
    96740,
    96741,
    96745,
    96746,
    96748,
    96752
  );
  script_osvdb_id(
    153730,
    153731,
    153732,
    153733,
    153734,
    153735,
    153736,
    153737,
    153738,
    153739,
    153740,
    153741
  );
  script_xref(name:"MSFT", value:"MS17-014");
  script_xref(name:"MSKB", value:"3172431");
  script_xref(name:"MSKB", value:"3172457");
  script_xref(name:"MSKB", value:"3172464");
  script_xref(name:"MSKB", value:"3172540");
  script_xref(name:"MSKB", value:"3172542");
  script_xref(name:"MSKB", value:"3178673");
  script_xref(name:"MSKB", value:"3178674");
  script_xref(name:"MSKB", value:"3178676");
  script_xref(name:"MSKB", value:"3178677");
  script_xref(name:"MSKB", value:"3178678");
  script_xref(name:"MSKB", value:"3178680");
  script_xref(name:"MSKB", value:"3178682");
  script_xref(name:"MSKB", value:"3178683");
  script_xref(name:"MSKB", value:"3178684");
  script_xref(name:"MSKB", value:"3178685");
  script_xref(name:"MSKB", value:"3178686");
  script_xref(name:"MSKB", value:"3178687");
  script_xref(name:"MSKB", value:"3178689");
  script_xref(name:"MSKB", value:"3178690");
  script_xref(name:"MSKB", value:"3178694");
  script_xref(name:"IAVA", value:"2017-A-0060");

  script_name(english:"MS17-014: Security Update for Microsoft Office (4013241)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application, Office Web Apps, or SharePoint
Server installed on the remote Windows host is missing a security
update. It is, therefore, affected by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist
    in Microsoft Office software due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit these, by convincing a user to open a
    specially crafted document file, to execute arbitrary
    code in the context of the current user. (CVE-2017-0006,
    CVE-2017-0019, CVE-2017-0020, CVE-2017-0030,
    CVE-2017-0031, CVE-2017-0052, CVE-2017-0053)

  - An information disclosure vulnerability exists in
    Microsoft Office due to improper disclosure of memory
    contents. An unauthenticated, remote attacker can
    exploit this to disclose sensitive system memory
    information by convincing a user to open a specially
    crafted document file. (CVE-2017-0027)

  - A denial of service vulnerability exists in Microsoft
    Office that allows an unauthenticated, remote attacker
    to cause Office to stop responding by convincing a user
    to open a specially crafted document file.
    (CVE-2017-0029)

  - An out-of-bounds read error exists in Microsoft Office
    due to an uninitialized variable. A local attacker can
    exploit this to disclose memory contents by opening a
    specially crafted document file. (CVE-2017-0105)

  - An cross-site scripting (XSS) vulnerability exists in
    Microsoft SharePoint Server due to improper validation
    of input before returning it to users. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-0107)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS17-014");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, and 2016; Microsoft Excel 2007, 2010, 2013, and 2016;
Microsoft Word 2007, 2010, 2013, and 2016; Microsoft Office
Compatibility Pack; Microsoft Excel Viewer; Microsoft Word Viewer;
Microsoft SharePoint Server 2007, 2010, and 2013; Microsoft SharePoint
Foundation 2013; and Microsoft Office Web Apps Server 2010 and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies(
    "office_installed.nasl",
    "microsoft_sharepoint_installed.nbin",
    "microsoft_owa_installed.nbin",
    "microsoft_office_compatibility_pack_installed.nbin",
    "microsoft_excel_viewer_installed.nbin",
    "microsoft_word_viewer_installed.nbin",
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

bulletin = 'MS17-014';
kbs = make_list(
  '3172431', # Excel Services on SharePoint Server 2013 SP1
  '3172457', # Office Web Apps Server 2013 SP1
  '3172464', # Word 2013 SP1
  '3172540', # SharePoint Foundation 2013 SP1
  '3172542', # Excel 2013 SP1
  '3178673', # Excel 2016
  '3178674', # Word 2016
  '3178676', # Excel 2007 SP3
  '3178677', # Office Compatibility Pack SP3
  '3178678', # Excel Services on SharePoint Server 2007 SP3
  '3178680', # Excel Viewer
  '3178682', # Office Compatibility Pack SP3
  '3178683', # Word 2007 SP3
  '3178684', # Word Automation Services on SharePoint Server 2010 SP2
  '3178685', # Excel Services on SharePoint Server 2010 SP2
  '3178686', # Office 2010 SP2
  '3178687', # Word 2010 SP2
  '3178689', # Office Web Apps 2010 SP2
  '3178690', # Excel 2010 SP2
  '3178694'  # Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

registry_init();

vuln = FALSE;

######################################################################
# Office 2010
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, path, prod;
  office_vers = hotfix_check_office_version();

  ######################################################################
  # Office 2010 Checks
  # wwlibcxm.dll only exists if KB2428677 is installed
  ######################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      path = hotfix_get_officeprogramfilesdir(officever:"14.0");
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7179.5000", path:path, bulletin:bulletin, kb:"3178686", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

######################################################################
# Excel 2007, 2010, 2013, 2016
######################################################################
function perform_excel_checks()
{
  local_var excel_checks, kb16;

  kb16 = "3178673";
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6765.5000", "kb", "3178676"),
    "14.0", make_array("sp", 2, "version", "14.0.7179.5000", "kb", "3178690"),
    "15.0", make_array("sp", 1, "version", "15.0.4911.1000", "kb", "3172542"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4510.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.6965.2140", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7369.2120", "channel", "Deferred", "channel_version", "1609", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2071", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7870.2024", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Word 2007, 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "3178674";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6765.5000", "kb", "3178683"),
    "14.0", make_array("sp", 2, "version", "14.0.7179.5000", "kb", "3178687"),
    "15.0", make_array("sp", 1, "version", "15.0.4911.1000", "kb", "3172464"),
    "16.0", make_nested_list(
        make_array("sp", 0, "version", "16.0.4510.1000", "channel", "MSI", "kb", kb16),
          make_array("sp", 0, "version", "16.0.6965.2140", "channel", "Deferred", "kb", kb16),
            make_array("sp", 0, "version", "16.0.7369.2120", "channel", "Deferred", "channel_version", "1609", "kb", kb16),
              make_array("sp", 0, "version", "16.0.7766.2071", "channel", "First Release for Deferred", "kb", kb16),
                make_array("sp", 0, "version", "16.0.7870.2024", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Compatibility Pack
######################################################################
function perform_comppack_checks()
{
  local_var excel_compat_checks, install, installs, path;

  ######################################################################
  # Excel Compatibility Pack
  ######################################################################
  excel_compat_checks = make_array(
    "12.0", make_array("version", "12.0.6765.5000", "kb", "3178677")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:excel_compat_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Compatibility Pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  if (!isnull(installs))
  {
    foreach install (keys(installs))
    {
      path = installs[install];
      path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
      if(hotfix_check_fversion(path:path, file:"wrd12cnv.dll", version:"12.0.6765.5000",  kb:"3178682", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

######################################################################
# Office Viewers
######################################################################
function perform_viewer_checks()
{
  local_var excel_vwr_checks, word_vwr_checks;

  ######################################################################
  # Excel Viewer
  ######################################################################
  excel_vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6765.5000", "kb", "3178680")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  word_vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8440.0", "kb", "3178694")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
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
      else if (owa_install["Product"] == "2013")
      {
        owa_2013_path = owa_install["path"];
        owa_2013_sp = owa_install["SP"];
      }
    }
  }

  ######################################################################
  # Office Web Apps 2010 SP2
  ######################################################################
  if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
  {
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7179.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3178689", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4911.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3172457", product:"Office Web Apps 2013") == HCF_OLDER)
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
    if (install["Product"] == "2013")
    {
      sps_2013_path = install['path'];
      sps_2013_sp = install['SP'];
      sps_2013_edition = install['Edition'];
    }
    else if (install["Product"] == "2010")
    {
      sps_2010_path = install['path'];
      sps_2010_sp = install['SP'];
      sps_2010_edition = install['Edition'];
    }
    else if (install["Product"] == "2007")
    {
      sps_2007_path = install['path'];
      sps_2007_sp = install['SP'];
      sps_2007_edition = install['Edition'];
    }
  }

  commonfiles = hotfix_get_commonfilesdir();
  if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

  ######################################################################
  # SharePoint Server 2013 SP1 - Excel Services
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4911.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3172431", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services / Excel Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7179.5000", path:path, bulletin:bulletin, kb:"3178684", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7179.5000", path:path, bulletin:bulletin, kb:"3178685", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2007 SP3 - Excel Services
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6765.5000", path:path, bulletin:bulletin, kb:"3178678", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Foundation 2013 SP1
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Foundation")
  {
    if(commonfiles) path = hotfix_append_path(path:commonfiles, value:"Microsoft Shared\Web Server Extensions\15\BIN");
    else path = hotfix_append_path(path:sps_2013_path, value:"BIN");
    if (hotfix_check_fversion(file:"onetutil.dll", version:"15.0.4911.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3172540", product:"Office Sharepoint Foundation 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

perform_office_checks();
perform_excel_checks();
perform_word_checks();
perform_comppack_checks();
perform_viewer_checks();
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
