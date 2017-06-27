#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94634);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/23 14:39:44 $");

  script_cve_id(
    "CVE-2016-7213",
    "CVE-2016-7228",
    "CVE-2016-7229",
    "CVE-2016-7230",
    "CVE-2016-7231",
    "CVE-2016-7232",
    "CVE-2016-7233",
    "CVE-2016-7234",
    "CVE-2016-7235",
    "CVE-2016-7236",
    "CVE-2016-7244",
    "CVE-2016-7245"
  );
  script_bugtraq_id(
    93993,
    93994,
    93995,
    93996,
    94005,
    94006,
    94020,
    94022,
    94025,
    94026,
    94029,
    94031
  );
  script_osvdb_id(
    146922,
    146923,
    146924,
    146925,
    146926,
    146927,
    146928,
    146929,
    146930,
    146931,
    146932,
    146933
  );
  script_xref(name:"MSFT", value:"MS16-133");
  script_xref(name:"IAVA", value:"2016-A-0319");

  script_name(english:"MS16-133: Security Update for Microsoft Office (3199168)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application installed on the remote Windows host
is missing a security update. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist
    due to improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit these by
    convincing a user to visit a specially crafted website
    or open a specially crafted Office file, resulting in
    the execution of arbitrary code in the context of the
    current user. (CVE-2016-7213, CVE-2016-7228,
    CVE-2016-7229, CVE-2016-7230, CVE-2016-7231,
    CVE-2016-7232, CVE-2016-7234, CVE-2016-7235,
    CVE-2016-7236, CVE-2016-7245)

  - An information disclosure vulnerability exists due to an
    out-of-bounds read error caused by an uninitialized
    variable. An unauthenticated, remote attacker can exploit
    this by convincing a user to open a specially crafted
    Office file, resulting in the disclosure of memory
    contents. (CVE-2016-7233)

  - A denial of service vulnerability exists due to improper
    handling of objects in memory. An unauthenticated,
    remote attacker can exploit this by convincing a user to
    open a specially crafted file, resulting in a crash of
    the application. (CVE-2016-7244)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-133");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Excel 2007, 2010, 2013,
2013 RT, and 2016; Microsoft PowerPoint 2010; Microsoft Word 2007,
2010, 2013, and 2013 RT; Office Compatibility Pack; Excel Viewer;
PowerPoint Viewer; Word Viewer; Microsoft SharePoint Server 2010 and
2013; and Office Web Apps 2010 and 2013");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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

bulletin = 'MS16-133';
kbs = make_list(
  '2986253', # Office 2007 SP3
  '3115120', # Office 2010 SP2
  '3115135', # Office 2016
  '3115153', # Office 2013 SP1
  '3118378', # PowerPoint 2010 SP2
  '3118381', # SharePoint Excel Services 2010 SP2
  '3118382', # PowerPoint Viewer
  '3118390', # Excel 2010 SP2
  '3118395', # Excel 2007 SP3
  '3118396', # Office 2007 SP3
  '3127889', # Office Compatibility Pack SP3
  '3127893', # Excel Viewer
  '3127904', # Excel 2016
  '3127921', # Excel 2013 SP1
  '3127927', # SharePoint Word Automation Services 2013 SP1 
  '3127929', # Office Web Apps Server 2013 SP1
  '3127932', # Word 2013 SP1
  '3127948', # Office Compatibility Pack SP3
  '3127949', # Word 2007
  '3127950', # SharePoint Word Automation Services 2010 SP2
  '3127951', # Office 2010 SP2
  '3127953', # Word 2010 SP2
  '3127954', # Office Web Apps Server 2010 SP2
  '3127962' # Word Viewer
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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7176.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3127954", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4875.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3127929", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
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
  }

  commonfiles = hotfix_get_commonfilesdir();
  if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

  ######################################################################
  # SharePoint Server 2013 SP1 - Word Automation Services
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4875.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3127927", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services / Excel Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7176.5000", path:path, bulletin:bulletin, kb:"3127950", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7176.5000", path:path, bulletin:bulletin, kb:"3118381", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
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
      if 
      (
        hotfix_check_fversion(file:"mso.dll", version:"12.0.6759.5000", path:path, bulletin:bulletin, kb:"3118396", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"vbe6.dll",      version: "6.5.10.57", path:path, bulletin:bulletin, kb:"2986253", product:prod) == HCF_OLDER
      )
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
      if (
        hotfix_check_fversion(file:"vbe7.dll",     version: "7.0.16.40"     , path:path, bulletin:bulletin, kb:"3115120", product: prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7176.5000", path:path, bulletin:bulletin, kb:"3127951", product: prod) == HCF_OLDER
      )
        vuln = TRUE;

      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (hotfix_check_fversion(file:"ppcore.dll", version: "14.0.7176.5000" , path:path, bulletin:bulletin, kb:"3118378", product:"PowerPoint 2010 SP2") == HCF_OLDER)
        vuln = TRUE;
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
      if (hotfix_check_fversion(file:"vbe7.dll", version: "7.1.10.56", path:path, bulletin:bulletin, kb:"3115153", product:prod) == HCF_OLDER)
        vuln = TRUE;
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
      if (hotfix_check_fversion(file:"vbe7.dll", version:"7.1.10.56", path:path, bulletin:bulletin, kb:"3115135", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var excel_checks, word_checks, onenote_checks, outlook_checks, ppt_vwr_checks, excel_compat_checks,excel_vwr_checks,word_vwr_checks,powerpoint_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6759.5000", "kb", "3118395"),
    "14.0", make_array("sp", 2, "version", "14.0.7176.5000", "kb", "3118390"),
    "15.0", make_array("sp", 1, "version", "15.0.4875.1000", "kb", "3127921"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4456.1003", "channel", "MSI", "kb", "3127904"),
      make_array("sp", 0, "version", "16.0.6741.2088", "channel", "Deferred", "kb", "3127904"),
      make_array("sp", 0, "version", "16.0.6965.2105", "channel", "Deferred", "channel_version", "1605", "kb", "3127904"),
      make_array("sp", 0, "version", "16.0.7369.2055", "channel", "First Release for Deferred", "kb", "3127904"),
      make_array("sp", 0, "version", "16.0.7369.2055", "channel", "Current", "kb", "3127904")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Checks
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6759.5000", "kb", "3127949"),
    "14.0", make_array("sp", 2, "version", "14.0.7176.5000", "kb", "3127953"),
    "15.0", make_array("sp", 1, "version", "15.0.4875.1000", "kb", "3127932")
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  excel_vwr_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6759.5000", "kb", "3127893")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  word_vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8437.0", "kb", "3127962")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint Viewer 2010
  ######################################################################
  ppt_vwr_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7176.5000", "kb", "3118382")
  );
  if (hotfix_check_office_product(product:"PowerPointViewer", display_name:"PowerPoint Viewer", checks:ppt_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  excel_compat_checks = make_array(
    "12.0", make_array("version", "12.0.6759.5000", "kb", "3127889")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:excel_compat_checks, bulletin:bulletin))
    vuln = TRUE;

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
      if(hotfix_check_fversion(path:path, file:"wrd12cnv.dll", version:"12.0.6759.5000", kb:"3127948", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

perform_office_checks();
perform_office_product_checks();
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
