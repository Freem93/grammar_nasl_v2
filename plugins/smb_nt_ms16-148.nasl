#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95811);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/19 15:55:08 $");

  script_cve_id(
    "CVE-2016-7262",
    "CVE-2016-7263",
    "CVE-2016-7264",
    "CVE-2016-7265",
    "CVE-2016-7266",
    "CVE-2016-7267",
    "CVE-2016-7268",
    "CVE-2016-7275",
    "CVE-2016-7276",
    "CVE-2016-7277",
    "CVE-2016-7289",
    "CVE-2016-7290",
    "CVE-2016-7291",
    "CVE-2016-7298"
  );
  script_bugtraq_id(
    94662,
    94664,
    94665,
    94668,
    94670,
    94671,
    94672,
    94715,
    94718,
    94720,
    94721,
    94769
  );
  script_osvdb_id(
    148625,
    148626,
    148627,
    148628,
    148629,
    148630,
    148631,
    148632,
    148633,
    148634,
    148635,
    148636,
    148637,
    148638
  );
  script_xref(name:"MSFT", value:"MS16-148");
  script_xref(name:"IAVA", value:"2016-A-0345");

  script_name(english:"MS16-148: Security Update for Microsoft Office (3204068)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application or Microsoft Office Services and Web
Apps installed on the remote Windows host is missing a security
update. It is, therefore, affected by multiple vulnerabilities :

  - An arbitrary command execution vulnerability exists in
    Microsoft Office due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this by convincing a user to open a
    specially crafted Office file, resulting in a bypass of
    security restrictions and the execution of arbitrary
    commands. (CVE-2016-7262)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office software due to a failure to properly
    handle objects in memory. An unauthenticated, remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted Office file,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2016-7263,
    CVE-2016-7277, CVE-2016-7289, CVE-2016-7298)

  - Multiple information disclosure vulnerabilities exist in
    Microsoft Office software due to an out-of-bounds memory
    read error. An unauthenticated, remote attacker can
    exploit these vulnerabilities by convincing a user to
    open a specially crafted Office file, resulting in the
    disclosure of memory contents. (CVE-2016-7264,
    CVE-2016-7265, CVE-2016-7268, CVE-2016-7276,
    CVE-2016-7290, CVE-2016-7291)

  - An arbitrary command execution vulnerability exists in
    Microsoft Office due to improper validation of registry
    settings when running embedded content. An
    unauthenticated, remote attacker can exploit this by
    convincing a user to open a specially crafted document
    file multiple times, resulting in a bypass of security
    restrictions and the execution of arbitrary commands.
    (CVE-2016-7266)

  - A security bypass vulnerability exists in Microsoft
    Office due to improper parsing of file formats. An
    unauthenticated, remote attacker can exploit this by
    convincing a user to open a specially crafted Office
    file, resulting in a bypass security restrictions.
    (CVE-2016-7267)

  - An elevation of privilege vulnerability exists in
    Microsoft Office due to improper validation before
    loading libraries. A local attacker can exploit this,
    via a specially crafted application, to gain elevated
    privileges. (CVE-2016-7275)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-148");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Excel 2007, 2010, 2013,
2013 RT, and 2016; Microsoft Word 2007, 2010; Microsoft Publisher 2010
Office Compatibility Pack; Excel Viewer; Word Viewer; Microsoft
SharePoint Server 2007 and 2010; and Office Web Apps 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
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

bulletin = 'MS16-148';
kbs = make_list(
  '3128020', # Office 2007 SP3
  '2883033',
  '3127986', # Office 2016
  '3127968', # Office 2013 SP1
  '3128029', # SharePoint Excel Services 2010 SP2
  '3127892', # SharePoint Excel Services 2007 SP3
  '3128037', # Excel 2010 SP2
  '3128019', # Excel 2007 SP3
  '3128025', # Word 2007 SP3
  '3128022', # Office Compatibility Pack SP3
  '3128024',
  '3128023', # Excel Viewer
  '3128016', # Excel 2016
  '3128008', # Excel 2013 SP1
  '3128026', # SharePoint Word Automation Services 2010 SP2
  '3118380', # Office 2010 SP2
  '3128032',
  '2889841',
  '3128034', # Word 2010 SP2
  '3114395', # Publisher 2010 SP2
  '3128035', # Office Web Apps Server 2010 SP2
  '3128044', # Word Viewer
  '3128043',
  '3127995'
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
    }
  }

  ######################################################################
  # Office Web Apps 2010 SP2
  ######################################################################
  if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
  {
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7177.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3128035", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var sps_2007_path, sps_2007_sp, sps_2007_edition;
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
  # SharePoint Server 2010 SP2 - Word Automation Services / Excel Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7177.5000", path:path, bulletin:bulletin, kb:"3128026", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;

    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7177.5000", path:path, bulletin:bulletin, kb:"3128029", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2007 SP3 - Excel Services
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6762.5000", path:path, bulletin:bulletin, kb:"3127892", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
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
      if (
        hotfix_check_fversion(file:"mso.dll", version:"12.0.6762.5000", path:path, bulletin:bulletin, kb:"3128020", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"usp10.dll", version:"1.0626.6002.24030", path:path, bulletin:bulletin, kb:"2883033", product:prod) == HCF_OLDER
      ) vuln = TRUE;
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
        hotfix_check_fversion(file:"mso.dll", version:"14.0.7177.5000", path:path, bulletin:bulletin, kb:"3118380", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7177.5000", path:path, bulletin:bulletin, kb:"3128032", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"usp10.dll", version:"1.0626.7601.23585", path:path, bulletin:bulletin, kb:"2889841", product:prod) == HCF_OLDER
      ) vuln = TRUE;
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
      if (hotfix_check_fversion(file:"msointl.dll", version:"15.0.4869.1000", path:path, bulletin:bulletin, kb:"3127968", product:prod) == HCF_OLDER)
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
      if (hotfix_check_fversion(file:"msointl.dll", version:"16.0.4471.1000", path:path, bulletin:bulletin, kb:"3127986", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var excel_checks, word_checks, onenote_checks, outlook_checks, ppt_vwr_checks, excel_compat_checks,excel_vwr_checks,word_vwr_checks,powerpoint_checks,publisher_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6762.5000", "kb", "3128019"),
    "14.0", make_array("sp", 2, "version", "14.0.7177.5000", "kb", "3128037"),
    "15.0", make_array("sp", 1, "version", "15.0.4885.1000", "kb", "3128008"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4471.1000", "channel", "MSI", "kb", "3128016"),
      make_array("sp", 0, "version", "16.0.6741.2098", "channel", "Deferred", "kb", "3128016"),
      make_array("sp", 0, "version", "16.0.6965.2115", "channel", "Deferred", "channel_version", "1605", "kb", "3128016"),
      make_array("sp", 0, "version", "16.0.7369.2095", "channel", "First Release for Deferred", "kb", "3128016"),
      make_array("sp", 0, "version", "16.0.7571.2075", "channel", "Current", "kb", "3128016")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Checks
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6762.5000", "kb", "3128025"),
    "14.0", make_array("sp", 2, "version", "14.0.7177.5000", "kb", "3128034")
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Publisher Checks
  ######################################################################
  publisher_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "3114395")
  );
  if (hotfix_check_office_product(product:"Publisher", checks:publisher_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  excel_vwr_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6762.5000", "kb", "3128023")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  word_vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8438.0", "kb", "3128044")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Compatibility pack
  ######################################################################
  excel_compat_checks = make_array(
    "12.0", make_array("version", "12.0.6762.5000", "kb", "3128022")
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
      if(hotfix_check_fversion(path:path, file:"wrd12cnv.dll", version:"12.0.6762.5000", kb:"3128024", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
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
