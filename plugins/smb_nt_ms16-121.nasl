#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94016);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/12 19:57:01 $");

  script_cve_id("CVE-2016-7193");
  script_bugtraq_id(93372);
  script_osvdb_id(145517);
  script_xref(name:"MSFT", value:"MS16-121");
  script_xref(name:"IAVA", value:"2016-A-0280");

  script_name(english:"MS16-121: Security Update for Microsoft Office (3194063)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote host is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application installed on the remote Windows host
is missing a security update. It is, therefore, affected by a remote
code execution vulnerability due to improper handling of RTF files. An
unauthenticated, remote attacker can exploit this by convincing a user
to open a specially crafted Office file, resulting in the execution of
arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-121");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Word 2007, 2010, 2013,
2013 RT, and 2016; Microsoft Office Compatibility Pack; Microsoft Word
Viewer; Microsoft SharePoint Server 2010 and 2013; Microsoft Office
Web Apps 2010 and 2013; and Office Online Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/10/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
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

bulletin = 'MS16-121';
kbs = make_list(
  '3118307', # Office Compatibility Pack SP3
  '3118308', # Word 2007 SP3
  '3118311', # Office 2010 SP2
  '3118312', # Word 2010 SP2
  '3118331', # Word 2016
  '3118345', # Word 2013 SP1
  '3118352', # Word Automation Services on SharePoint Server 2013 SP1
  '3118360', # Office Web Apps Server 2013 SP1
  '3118377', # Word Automation Services on SharePoint Server 2010 SP2
  '3118384', # Office Web Apps 2010 SP2
  '3127897', # Office Online Server
  '3127898', # Word Viewer
  '3193438', # Word 2016 for Mac
  '3193442'  # Word for Mac 2011
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
    path = hotfix_append_path(path:office_online_server_path, value:"UlsController");
    if (hotfix_check_fversion(file:"uls.dll", version:"16.0.6228.1036", min_version:"16.0.6000.0", path:path, bulletin:bulletin, kb:"3127897", product:"Office Online Server") == HCF_OLDER)
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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7174.5001", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3118384", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4867.1002", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3118360", product:"Office Web Apps 2013") == HCF_OLDER)
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
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4867.1002", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3118352", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7174.5001", path:path, bulletin:bulletin, kb:"3118377", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }
}

function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, kb;
  office_vers = hotfix_check_office_version();

  ######################################################################
  # Office 2010 Checks
  ######################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      
      # wwlibcxm.dll only exists if KB2428677 is installed
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7174.5001", path:path, bulletin:bulletin, kb:"3118311", product:prod) == HCF_OLDER)
          vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var word_checks, word_compat_checks, word_vwr_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Word Checks
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6758.5000", "kb", "3118308"),
    "14.0", make_array("sp", 2, "version", "14.0.7174.5001", "kb", "3118312"),
    "15.0", make_array("sp", 1, "version", "15.0.4867.1002", "kb", "3118345"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4444.1003", "channel", "MSI", "kb", "3118331"),
      make_array("sp", 0, "version", "16.0.6741.2081", "channel", "Deferred", "kb", "3118331"),
      make_array("sp", 0, "version", "16.0.6965.2092", "channel", "Deferred", "channel_version", "1605", "kb", "3118331"),
      make_array("sp", 0, "version", "16.0.7369.2038", "channel", "First Release for Deferred", "kb", "3118331"),
      make_array("sp", 0, "version", "16.0.7369.2038", "channel", "Current", "kb", "3118331")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################

  word_vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8436.0", "kb", "3127898")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
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
      if(hotfix_check_fversion(path:path, file:"wrd12cnv.dll", version:"12.0.6758.5000", kb:"3118307", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
        vuln = TRUE;
    }
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
