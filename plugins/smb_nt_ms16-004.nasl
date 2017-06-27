#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87882);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/06 19:24:46 $");

  script_cve_id(
    "CVE-2015-6117",
    "CVE-2016-0010",
    "CVE-2016-0011",
    "CVE-2016-0012",
    "CVE-2016-0035"
  );
  script_bugtraq_id(
    80028,
    80029,
    80030,
    80031,
    80032
  );
  script_osvdb_id(
    132782,
    132783,
    132784,
    132785,
    132790
  );
  script_xref(name:"MSFT", value:"MS16-004");
  script_xref(name:"IAVA", value:"2016-A-0011");

  script_name(english:"MS16-004: Security Update for Microsoft Office to Address Remote Code Execution (3124585)");
  script_summary(english:"Checks the Office, SharePoint, and Visual Basic Runtime versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Word, Word
Viewer, Excel, Excel Viewer, PowerPoint, Visio, SharePoint, Visual
Basic, or Microsoft Office Compatibility Pack installed that is
affected by multiple vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist in
    Microsoft SharePoint due to improper enforcement of
    Access Control Policy (ACP) configuration settings. A
    remote attacker can exploit these vulnerabilities, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2015-6117,
    CVE-2016-0011)

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office due to improper handling of objects in
    memory. An attacker can exploit these vulnerabilities by
    convincing a user to open a specially crafted file in
    Microsoft Office, resulting in execution of arbitrary
    code in the context of the current user. (CVE-2016-0010,
    CVE-2016-0035)

  - An information disclosure vulnerability exists in
    Microsoft Office due to a failure to use the Address
    Space Layout Randomization (ASLR) security feature. An
    attacker can exploit this to predict memory offsets of
    specific instructions in a call stack. (CVE-2016-0012)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-004");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, 2016, Word, Word Viewer, Excel, Excel Viewer, PowerPoint,
Visio, SharePoint Server 2013, SharePoint Foundation 2013, Microsoft
Office Compatibility Pack, and Visual Basic 6.0 Runtime.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-004';
kbs = make_list(
  2881067,  # Office 2007 SP3 #
  3114541,  # Office 2007 SP3 #

  3114540,  # 2007 Excel SP3 #
  3114429,  # 2007 PP SP3 #
  3114421,  # 2007 Visio #
  3114549,  # 2007 Word SP3 #

  2881029, # Office 2010 SP2 #
  3114553, # Office 2010 SP2 #
  3114554, # Office 2010 SP2 #

  3114564, # 2010 Excel SP2 #
  3114396, # 2010 PP SP2  #
  3114402, # 2010 Visio #
  3114557, # 2010 Word SP2 #

  3039794, # Office 2013 SP1 #
  3114486, # Office 2013 SP1 #
  
  3114504, # 2013 Excel SP1 #
  3114482, # 2013 PP SP1 #
  3114489, # 2013 Visio #
  3114494, # 2013 Word SP1 #

  2920727, # Office 2016 #
  3114527, # Office 2016 #

  3114520, # 2016 Excel #
  3114518, # 2016 PP #
  3114511, # 2016 Visio #
  3114526, # 2016 Word #

  3114546, # Compat Pack SP3 #
  3114547, # Excel Viewer #
  3114569, # Word Viewer

  3114503, # Sharepoint 2013 SP1 #

  3096896 # Visual Basic Runtime 6.0 #
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();

vuln = FALSE;

function check_mscomctlocx(product, kb, bulletin)
{
  if (hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.46", dir:"\System32", bulletin:bulletin, kb:kb, product:product) ||
      hotfix_is_vulnerable(file:"mscomctl.ocx", version:"6.1.98.46", dir:"\SysWOW64", bulletin:bulletin, kb:kb, product:product)
  ) vuln = TRUE;
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
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"Microsoft Shared\Office12");
      if (
          hotfix_check_fversion(file:"mso.dll",     version: "12.0.6741.5000" , path:path, bulletin:bulletin, kb:"3114541", product:"Microsoft Office 2007 SP3") == HCF_OLDER ||
          hotfix_check_fversion(file:"ppcore.dll",    version: "12.0.6741.5000" , path:path, bulletin:bulletin, kb:"3114429", product:"PowerPoint 2007 SP3"      ) == HCF_OLDER
      ) vuln = TRUE;
    }

    # Only 32 bit arches affected
    if (get_kb_item("SMB/Office/12.0/Bitness") != "x64")
      check_mscomctlocx(product:"Microsoft Office 2007 SP3", bulletin:bulletin, kb:"2881067");
  }

  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"mso.dll",   version: "14.0.7165.5000", path:path, bulletin:bulletin, kb:"3114553", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7165.5000", path:path, bulletin:bulletin, kb:"3114554", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"ppcore.dll",    version: "14.0.7165.5000" , path:path, bulletin:bulletin, kb:"3114396", product:"PowerPoint 2010 SP2"      ) == HCF_OLDER
      ) vuln = TRUE;

      # Only 32 bit arches affected
      if (get_kb_item("SMB/Office/14.0/Bitness") != "x64")
        check_mscomctlocx(product:"Microsoft Office 2010 SP2", bulletin:bulletin, kb:"2881029");
    }
  }

  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && int(office_sp) <= 1)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"15.0"), value:"Microsoft Shared\Office15");
      if (
        hotfix_check_fversion(file:"mso.dll", version:"15.0.4787.1002", path:path, bulletin:bulletin, kb:"3114486", product:"Microsoft Office 2013 SP1") == HCF_OLDER ||
        hotfix_check_fversion(file:"ppcore.dll",    version: "15.0.4787.1000" , path:path, bulletin:bulletin, kb:"3114482", product:"PowerPoint 2013 SP1"      ) == HCF_OLDER
      ) vuln = TRUE;

      # Only 32 bit arches affected
      if (get_kb_item("SMB/Office/15.0/Bitness") != "x64")
        check_mscomctlocx(product:"Microsoft Office 2013 SP1", bulletin:bulletin, kb:"3039794");
    }
  }

  local_var x86path,x64path;
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && int(office_sp) <= 1)
    {
      path = hotfix_get_officeprogramfilesdir(officever:"16.0");
      x86path = hotfix_append_path(path:path, value:"Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\Office16");
      x64path = hotfix_append_path(path:path, value:"Microsoft Office\root\VFS\ProgramFilesCommonX64\Microsoft Shared\Office16");

      if (
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.4297.1000", channel:"MSI", channel_product:"Office", path:x86path, bulletin:bulletin, kb:"3114527", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.4297.1000", channel:"MSI", channel_product:"Office", path:x64path, bulletin:bulletin, kb:"3114527", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"ppcore.dll", version:"16.0.4324.1000", channel:"MSI", channel_product:"PowerPoint", path:path, bulletin:bulletin, kb:"3114518", product:"PowerPoint 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.6001.1054", channel:"First Release for Deferred", channel_product:"Office", path:x86path, bulletin:bulletin, kb:"3114527", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.6001.1054", channel:"First Release for Deferred", channel_product:"Office", path:x64path, bulletin:bulletin, kb:"3114527", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"ppcore.dll", version:"16.0.6001.1054", channel:"First Release for Deferred", channel_product:"PowerPoint", path:path, bulletin:bulletin, kb:"3114518", product:"PowerPoint 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.6366.2056", channel:"Current", channel_product:"Office", path:x86path, bulletin:bulletin, kb:"3114527", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"Msores.dll", version:"16.0.6366.2056", channel:"Current", channel_product:"Office", path:x64path, bulletin:bulletin, kb:"3114527", product:"Microsoft Office 2016") == HCF_OLDER ||
        hotfix_check_fversion(file:"ppcore.dll", version:"16.0.6366.2056", channel:"Current", channel_product:"PowerPoint", path:path, bulletin:bulletin, kb:"3114518", product:"PowerPoint 2016") == HCF_OLDER
      ) vuln = TRUE;

      # Only 32 bit arches affected
      if (get_kb_item("SMB/Office/16.0/Bitness") != "x64")
        check_mscomctlocx(product:"Microsoft Office 2016", bulletin:bulletin, kb:"2920727");
    }
  }
}

function perform_vb6_runtime_check()
{
  local_var hklm;
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  if (!isnull(get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\VisualStudio\6.0\Setup\Microsoft Visual Basic\ProductDir")))
    check_mscomctlocx(product:"Microsoft Visual Basic 6.0", bulletin:bulletin, kb:"3096896");
  RegCloseKey(handle:hklm);
  close_registry();
}

function perform_office_product_checks()
{
  local_var checks, vwr_checks, compat_checks, kb;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6742.5000", "kb", "3114540"),
    "14.0", make_array("sp", 2, "version", "14.0.7165.5002", "kb", "3114564"),
    "15.0", make_array("sp", 1, "version", "15.0.4787.1002", "kb", "3114504"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4324.1001", "channel", "MSI", "kb", "3114520"),
      make_array("sp", 0, "version", "16.0.6001.1054", "channel", "First Release for Deferred", "kb", "3114520"),
      make_array("sp", 0, "version", "16.0.6366.2056", "channel", "Current", "kb", "3114520")
    )
  );
  if (hotfix_check_office_product(product:"Excel", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Checks
  ######################################################################
  checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6741.5000", "kb", "3114549"),
    "14.0", make_array("sp", 2, "version", "14.0.7165.5000", "kb", "3114557"),
    "15.0", make_array("sp", 1, "version", "15.0.4787.1000", "kb", "3114494"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4324.1000", "channel", "MSI", "kb", "3114526"),
      make_array("sp", 0, "version", "16.0.6001.1054", "channel", "First Release for Deferred", "kb", "3114526"),
      make_array("sp", 0, "version", "16.0.6366.2056", "channel", "Current", "kb", "3114526")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Viewer
  ######################################################################
  vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6742.5000", "kb", "3114547")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  foreach install (installs)
  {
    path = installs[install];
    if (hotfix_is_vulnerable(path:path, file:"mso.dll", version:"11.0.8423.0", bulletin:bulletin, kb:"3114569"))
      vuln = TRUE;
  }

  ######################################################################
  # Excel and Word Compatibility pack
  ######################################################################
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6742.5000", "kb", "3114546")
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
    if ("12.0" >!< version && "14.0" >!< version && "15.0" >!< version && "16.0" >!< version)
      continue;
    path = installs[install];
    if ("12.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"12.0.6741.5000", min_version:"12.0.6000.0", bulletin:bulletin, kb:"3114421"))
      vuln = TRUE;
    if ("14.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"14.0.7165.5000", min_version:"14.0.6500.0", bulletin:bulletin, kb:"3114402"))
      vuln = TRUE;
    if ("15.0" >< version && hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"15.0.4787.1000", min_version:"15.0.4000.0", bulletin:bulletin, kb:"3114489"))
      vuln = TRUE;
    if ("16.0" >< version && 
      (
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.4324.1000", channel:"MSI", channel_product:"Visio", bulletin:bulletin, kb:"3114511") ||
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.6001.1054", channel:"First Release for Deferred", channel_product:"Visio", bulletin:bulletin, kb:"3114511") ||
        hotfix_is_vulnerable(path:path, file:"Visio.exe", version:"16.0.6366.2056", channel:"Current", channel_product:"Visio", bulletin:bulletin, kb:"3114511")
      )
    ) vuln = TRUE;
  }
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var installs, install, path, prod;

  sps_2013_path = NULL;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install['Product'] == "2013")
    {
      sps_2013_path = install['path'];
      sps_2013_sp = install['SP'];
      sps_2013_edition = install['Edition'];
      break;
    }
  }

  ######################################################################
  # SharePoint Server 2013
  ######################################################################
  # In this case the fix for SharePoint Server and SharePoint Foundation
  # are the same, this is not always the case
  if (sps_2013_path)
  {
    if (sps_2013_sp == "1")
    {
      prod = "SharePoint " + sps_2013_edition + " SP1";
      path = hotfix_append_path(path:hotfix_get_commonfilesdir(), value:"Microsoft Shared\Web Server Extensions\15\BIN\");
      if (hotfix_check_fversion(file:"onetutil.dll", version:"15.0.4787.1000", path:path, bulletin:bulletin, kb:"3114503", product:prod) == HCF_OLDER)
      {
        set_kb_item(name:"www/0/XSS", value:TRUE);
        vuln = TRUE;
      }
    }
  }
}

perform_office_checks();
perform_office_product_checks();
perform_visio_checks();
perform_sharepoint_checks();
perform_vb6_runtime_check();

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
