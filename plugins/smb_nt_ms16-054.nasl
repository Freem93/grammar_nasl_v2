#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91004);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/13 20:59:27 $");

  script_cve_id(
    "CVE-2016-0126",
    "CVE-2016-0140",
    "CVE-2016-0183",
    "CVE-2016-0198"
  );
  script_bugtraq_id(
    89938,
    89953,
    89962
  );
  script_osvdb_id(
    138345,
    138346,
    138347,
    138348
  );
  script_xref(name:"MSFT", value:"MS16-054");
  script_xref(name:"IAVA", value:"2016-A-0124");

  script_name(english:"MS16-054: Security Update for Microsoft Office (3155544)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote Windows host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Microsoft Office installed on the remote Windows host
is affected by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to improper handling of objects in memory. An
    unauthenticated, remote attacker can exploit these
    vulnerabilities by convincing a user to visit a
    specially crafted website or open a specially crafted
    file, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2016-0126,
    CVE-2016-0140, CVE-2016-0198)

  - A remote code execution vulnerability exists in the
    Windows Font library due to improper handling of
    embedded fonts. An unauthenticated, remote attacker can
    exploit this by convincing a user to visit a specially
    crafted website or open a specially crafted file,
    resulting in the execution arbitrary code in the context
    of the current user. (CVE-2016-0183)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/en-us/library/security/ms16-054");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Word 2007, 2010, 2013,
2013 RT, and 2016; Word Viewer; Microsoft Office Compatibility Pack;
Office Web Apps 2010; and Microsoft SharePoint Server 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
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

bulletin = 'MS16-054';
kbs = make_list(
  '2984938',
  '2984943',
  '3115116',
  '3115121',
  '3054984',
  '3101520',
  '3115123',
  '3115016',
  '3115025',
  '3115103',
  '3115094',
  '3115132',
  '3115117',
  '3115124'
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
        break;
      }
    }
  }

  ######################################################################
  # Office Web Apps 2010 SP2
  ######################################################################
  if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
  {
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7169.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3115124", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }
}

function perform_office_checks()
{
  local_var office_vers, office_sp, path;
  office_vers = hotfix_check_office_version();

  # 2007
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"12.0"), value:"Microsoft Office\Office12");
      if (
        hotfix_check_fversion(file:"oartconv.dll", version: "12.0.6748.5000" , path:path, bulletin:bulletin, kb:"2984938", product:"Microsoft Office 2007 SP3") == HCF_OLDER ||
        hotfix_check_fversion(file:"oart.dll", version: "12.0.6748.5000" , path:path, bulletin:bulletin, kb:"2984943", product:"Microsoft Office 2007 SP3") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  # 2010
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7169.5000", path:path, bulletin:bulletin, kb:"3115121", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"oartconv.dll", version: "14.0.7169.5000", path:path, bulletin:bulletin, kb:"3054984", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"oart.dll", version: "14.0.7169.5000", path:path, bulletin:bulletin, kb:"3101520", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  # 2013
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"15.0"), value:"Microsoft Office\Office15");
      if (
        hotfix_check_fversion(file:"office.dll", version: "15.0.4823.1000", path:path, bulletin:bulletin, kb:"3115016", product:"Microsoft Office 2013 SP1") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  # 2016
  if (office_vers['16.0'])
  {
    path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"16.0"), value:"Microsoft Office\root\Office16");
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && office_sp == 0)
    {
      if (
        hotfix_check_fversion(file:"mso40uires.dll", version:"16.0.4297.1000", path:path, bulletin:bulletin, kb:"3115103", product:"Microsoft Office 2016") == HCF_OLDER
      ) vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var checks, word_vwr_checks, vwr_checks, compat_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Word Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6748.5000", "kb", "3115116"),
    "14.0", make_array("sp", 2, "version", "14.0.7169.5000", "kb", "3115123"),
    "15.0", make_array("sp", 1, "version", "15.0.4823.1000", "kb", "3115025"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4378.1001", "channel", "MSI", "kb", "3115094"), 
      make_array("sp", 0, "version", "16.0.6001.1078", "channel", "Deferred", "kb", "3115094"),
      make_array("sp", 0, "version", "16.0.6741.2037", "channel", "First Release for Deferred", "kb", "3115094"),
      make_array("sp", 0, "version", "16.0.6868.2062", "channel", "Current", "kb", "3115094")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if(!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8428.0", "kb", "3115132")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;
  }

  ######################################################################
  # Word Compatibility pack
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6748.5000", kb:"3115115", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var installs, install, path, prod;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install["Product"] == "2010")
    {
      sps_2010_path = install['path'];
      sps_2010_sp = install['SP'];
      sps_2010_edition = install['Edition'];
      break;
    }
  }

  # Office Services and Web Apps
  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7169.5000", path:path, bulletin:bulletin, kb:"3115117", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
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
