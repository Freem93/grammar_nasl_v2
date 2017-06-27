#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89752);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/18 20:50:58 $");

  script_cve_id(
    "CVE-2016-0021",
    "CVE-2016-0057",
    "CVE-2016-0134"
  );
  script_bugtraq_id(
    84024,
    84026,
    84030
  );
  script_osvdb_id(
    135546,
    135548,
    135547
  );
  script_xref(name:"MSFT", value:"MS16-029");
  script_xref(name:"IAVA", value:"2016-A-0063");

  script_name(english:"MS16-029: Security Update for Microsoft Office to Address Remote Code Execution (3141806)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Office
Compatibility Pack, Office Web Apps, Microsoft SharePoint, Microsoft
Word, or Word Viewer installed that is affected by multiple
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office software due to improper handling of
    objects in memory. An attacker can exploit these, by
    convincing a user to open a specially crafted file, to
    execute arbitrary code in the context of the current
    user. (CVE-2016-0021, CVE-2016-0134)

  - A security feature bypass vulnerability exists in
    Microsoft Office software due to an improperly signed
    binary file. An attacker with write access to the target
    host can exploit this, by overwriting the file with a
    malicious binary with a similar configuration, to execute
    arbitrary code. (CVE-2016-0057).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/ms16-029");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, and 2016; Microsoft InfoPath 2007, 2010 and 2013; Microsoft
Word 2007, 2010, 2013, 2013 RT, and 2016; Word Viewer; SharePoint
Server 2010 and 2013; Microsoft Office Compatibility Pack; and Office
Web Apps 2010 and 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
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

bulletin = 'MS16-029';
kbs = make_list(
  '2956063', ## Office 2010 SP2
  '2956110', ## Office 2007 SP3
  '3039746', ## Office 2013 SP1
  '3114414', ## InfoPath 2010 SP2
  '3114426', ## InfoPath 2007 SP3
  '3114690', ## Office 2016
  '3114812', ## Word Viewer
  '3114814', ## Word Automation Services SharePoint 2013 SP1
  '3114821', ## Office Web Apps 2013 SP1
  '3114824', ## Word 2013 SP1
  '3114833', ## InfoPath 2013 SP1
  '3114855', ## Office 2016
  '3114866', ## Word Automation Services SharePoint 2010 SP2
  '3114873', ## Office 2010 SP2
  '3114878', ## Word 2010 SP2
  '3114880', ## Office Web Apps 2010 SP2
  '3114900', ## Office Compatibility Patch SP3
  '3114901'  ## Word 2007 SP3
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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7167.5000", min_version:"14.0.7015.1000", path:path, bulletin:bulletin, kb:"3114880", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # Office Web Apps 2013 SP1
  ######################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"ExcelServicesEcs\bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4805.1000", min_version:"15.0.4571.1500", path:path, bulletin:bulletin, kb:"3114821", product:"Office Web Apps 2013") == HCF_OLDER)
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
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"12.0"), value:"Microsoft Office\Office12");
      # InfoPath
      if(max_index(keys(get_kb_list("SMB/Office/InfoPath/12.0*/ProductPath"))) > 0)
      {
        path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"12.0"), value:"Microsoft Office\Office12");
        if(hotfix_is_vulnerable(path:path, file:"ipdesign.dll", version:"12.0.6744.5000", min_version:"12.0.0.0", bulletin:bulletin, kb:'3114426'))
          vuln = TRUE;
      }
      if (
        hotfix_check_fversion(file:"otkloadr.dll", version: "7.10.5079.0" , path:path + "ADDINS", bulletin:bulletin, kb:"2956110", product:"Microsoft Office 2007 SP3") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      # InfoPath
      if(max_index(keys(get_kb_list("SMB/Office/InfoPath/14.0*/ProductPath"))) > 0)
      {
        if(hotfix_is_vulnerable(path:path, file:"ipdesign.dll", version:"14.0.7167.5000", min_version:"14.0.0.0", bulletin:bulletin, kb:'3114414'))
          vuln = TRUE;
      }
      if (
        hotfix_check_fversion(file:"otkloadr.dll", version: "7.10.5079.0", path:path + "ADDINS", bulletin:bulletin, kb:"2956063", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      ) vuln = TRUE;
      if (
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7167.5001", path:path, bulletin:bulletin, kb:"3114873", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      ) vuln = TRUE;
    }
  }

  # Office 2013 SP1
  if (office_vers['15.0'])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"15.0"), value:"Microsoft Office\Office15");
      # InfoPath
      if(max_index(keys(get_kb_list("SMB/Office/InfoPath/15.0*/ProductPath"))) > 0)
      {
        if(hotfix_is_vulnerable(path:path, file:"ipdesign.dll", version:"15.0.4805.1000", min_version:"15.0.0.0", bulletin:bulletin, kb:'3114833'))
          vuln = TRUE;
      }
      if (hotfix_is_vulnerable(file:"otkloadr.dll", version:"7.10.5079.0", min_version:'7.0.0.0', path:path + "ADDINS", bulletin:bulletin, kb:"3039746"))
        vuln = TRUE;
    }
  }

  # Office 2016
  if (office_vers['16.0'])
  {
    path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"16.0"), value:"Microsoft Office\root\office16");
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && office_sp == 0)
    {
      if (hotfix_is_vulnerable(file:"otkloadr.dll", version:"7.10.5079.0", min_version:'7.0.0.0', path:path + "ADDINS", bulletin:bulletin, kb:"3114690"))
        vuln = TRUE;
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
    "12.0", make_array("sp", 3, "version", "12.0.6745.5000", "kb", "3114901"),
    "14.0", make_array("sp", 2, "version", "14.0.7167.5001", "kb", "3114878"),
    "15.0", make_array("sp", 1, "version", "15.0.4805.1001", "kb", "3114824"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4351.1001", "channel", "MSI", "kb", "3114855"),
      make_array("sp", 0, "version", "16.0.6001.1068", "channel", "Deferred", "kb", "3114855"),
      make_array("sp", 0, "version", "16.0.6741.2014", "channel", "First Release for Deferred", "kb", "3114855"),
      make_array("sp", 0, "version", "16.0.6568.2034", "channel", "Current", "kb", "3114855")
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
      "11.0", make_array("version", "11.0.8425.0", "kb", "3114812")
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
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6745.5000", kb: "3114900", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
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
      break;
    }
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7167.5000", path:path, bulletin:bulletin, kb:"3114866", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013
  ######################################################################
  if (sps_2013_path)
  {
    if (sps_2013_sp == "1")
    {
      if(sps_2013_edition == "Server")
      {
        path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
        if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4805.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:"3114814", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
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
