#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100103);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id(
    "CVE-2017-0254",
    "CVE-2017-0255",
    "CVE-2017-0261",
    "CVE-2017-0262",
    "CVE-2017-0281"
  );
  script_bugtraq_id(
    98101,
    98104,
    98107,
    98279,
    98297
  );
  script_osvdb_id(
    157224,
    157253,
    157254,
    157255,
    157256
  );
  script_xref(name:"MSKB", value:"2596904");
  script_xref(name:"MSKB", value:"3114375");
  script_xref(name:"MSKB", value:"3118310");
  script_xref(name:"MSKB", value:"3162040");
  script_xref(name:"MSKB", value:"3162054");
  script_xref(name:"MSKB", value:"3162069");
  script_xref(name:"MSKB", value:"3172458");
  script_xref(name:"MSKB", value:"3172475");
  script_xref(name:"MSKB", value:"3172482");
  script_xref(name:"MSKB", value:"3172532");
  script_xref(name:"MSKB", value:"3172536");
  script_xref(name:"MSKB", value:"3178633");
  script_xref(name:"MSKB", value:"3178638");
  script_xref(name:"MSKB", value:"3178729");
  script_xref(name:"MSKB", value:"3191835");
  script_xref(name:"MSKB", value:"3191836");
  script_xref(name:"MSKB", value:"3191839");
  script_xref(name:"MSKB", value:"3191841");
  script_xref(name:"MSKB", value:"3191843");
  script_xref(name:"MSKB", value:"3191858");
  script_xref(name:"MSKB", value:"3191863");
  script_xref(name:"MSKB", value:"3191865");
  script_xref(name:"MSKB", value:"3191880");
  script_xref(name:"MSKB", value:"3191881");
  script_xref(name:"MSKB", value:"3191885");
  script_xref(name:"MSKB", value:"3191886");
  script_xref(name:"MSKB", value:"3191887");
  script_xref(name:"MSKB", value:"3191888");
  script_xref(name:"MSKB", value:"3191890");
  script_xref(name:"MSKB", value:"3191895");
  script_xref(name:"MSKB", value:"3191899");
  script_xref(name:"MSKB", value:"3191904");
  script_xref(name:"MSKB", value:"3191909");
  script_xref(name:"MSKB", value:"3191913");
  script_xref(name:"MSKB", value:"3191914");
  script_xref(name:"MSKB", value:"3191915");
  script_xref(name:"IAVA", value:"2017-A-0143");

  script_name(english:"Security Update for Microsoft Office Products (May 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application, Office Web Apps, or SharePoint
Server installed on the remote Windows host is missing a security
update. It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software due to improper handling of
    objects in memory. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open a
    specially crafted Office document, to execute arbitrary
    code in the context of the current user. (CVE-2017-0254)

  - A cross-site scripting (XSS) vulnerability exists in
    Microsoft SharePoint Server due improper validation of
    user-supplied input in web requests. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-0255)

  - A remote code execution vulnerability exists in
    Microsoft Office due to improper handling of malformed
    graphics images. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted EPS file, to execute arbitrary code in the
    context of the current user. (CVE-2017-0261)

  - A remote code execution vulnerability exists in
    Microsoft Office when handling malformed graphics
    images. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted
    EPS file or visit a specially crafted website, to
    execute arbitrary code. (CVE-2017-0262)

  - A remote code execution vulnerability exists in
    Microsoft Office due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted
    file, to execute arbitrary code in the context of the
    current user. (CVE-2017-0281)");
  script_set_attribute(attribute:"see_also",value:"https://portal.msrc.microsoft.com/en-us/security-guidance/summary");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, and 2016; Microsoft Word 2007, 2010, 2013, and 2016; Skype
for Business 2016; Microsoft Word Viewer; Microsoft Office
Compatibility Pack; SharePoint Server 2010; SharePoint Enterprise
Server 2013 and 2016; SharePoint Foundation 2013; Word Automation
Services on Microsoft SharePoint Server 2010 and 2013; Microsoft
Office Project Server 2013; Microsoft Office Web Apps Server 2010 and
2013; and Office Online Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
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
    "microsoft_lync_server_installed.nasl",
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

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS17-05";
kbs = make_list(
  '2596904', # Office 2007 SP3
  '3114375', # Office 2016
  '3118310', # Office 2010 SP2
  '3162040', # Word Automation Services on SharePoint Server 2013 SP1
  '3162054', # SharePoint Foundation 2013 SP1
  '3162069', # SharePoint Server 2013 SP1
  '3172458', # Office 2013 SP1
  '3172475', # Sharepoint Server 2013 SP1
  '3172482', # SharePoint Server 2013 SP1
  '3172532', # SharePoint Server 2013 SP1
  '3172536', # SharePoint Server 2013 SP1
  '3178633', # SharePoint Server 2013 SP1
  '3178638', # SharePoint Server 2013 SP1
  '3178729', # Word 2013 SP1
  '3191835', # Office Compatibility Pack SP3
  '3191836', # Word 2007 SP3
  '3191839', # SharePoint Server 2010 SP2
  '3191839', # Word Automation Services on SharePoint Server 2010 SP2
  '3191841', # Office 2010 SP2
  '3191841', # Word 2010 SP2
  '3191843', # Word 2010 SP2
  '3191858', # Skype for Business 2016
  '3191863', # Office 2016
  '3191865', # Word 2016
  '3191880', # SharePoint Enterprise Server 2016
  '3191881', # Office 2016
  '3191885', # Office 2013 SP1
  '3191886', # SharePoint Server 2013 SP1
  '3191887', # Excel Services on SharePoint Server 2013
  '3191888', # Office Web Apps 2013 SP1
  '3191890', # Project Server 2013 SP1
  '3191895', # Office 2007 SP3
  '3191899', # Office 2010 SP2
  '3191904', # Office Web Apps 2010 SP2
  '3191909', # Office Word Viewer
  '3191913', # SharePoint Enterprise Server 2013 SP1
  '3191914', # SharePoint Foundation 2013 SP1
  '3191915'  # Office Online Server 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
global_var office_online_server_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office16.WacServer\InstallLocation"
);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

vuln = FALSE;
xss  = FALSE;
port = kb_smb_transport();

######################################################################
# Office 2007, 2010, 2013, 2016
######################################################################
function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, file, kb;
  office_vers = hotfix_check_office_version();

  ####################################################################
  # Office 2007 SP3 Checks
  ####################################################################
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      prod = "Microsoft Office 2007 SP3";
      path = hotfix_append_path(
        path  : hotfix_get_officecommonfilesdir(officever:"12.0"),
        value : "Microsoft Shared\Office12"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6768.5000", path:path, kb:"3191895", product:prod) == HCF_OLDER)
        vuln = TRUE;
      if (hotfix_check_fversion(file:"riched20.dll", version:"12.0.6768.5000", path:path, kb:"2596904", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2010 SP2 Checks
  # wwlibcxm.dll only exists if KB2428677 is installed
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7181.5000", path:path, kb:"3191899", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "\Microsoft Shared\GRPHFLT"
      );
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2010.1400.7181.5002", min_version:"2010.1400.0.0", path:path, kb:"3118310", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_get_officeprogramfilesdir(officever:"14.0");
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7181.5000", path:path, kb:"3191841", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2013 SP1 Checks
  ####################################################################
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      prod = "Microsoft Office 2013 SP1";
      common_path = hotfix_get_officecommonfilesdir(officever:"15.0");

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office15"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4927.1000", path:path, kb:"3191885", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\GRPHFLT"
      );
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2012.1500.4927.1002", min_version:"2012.1500.0.0", path:path, kb:"3172458", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2016 Checks
  ####################################################################
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && office_sp == 0)
    {
      prod = "Microsoft Office 2016";
      common_path = hotfix_get_officecommonfilesdir(officever:"16.0");

      kb   = "3191881";
      file = "mso.dll";
      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office16"
      );
      if (
        hotfix_check_fversion(file:file, version:"16.0.4534.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        # hotfix_check_fversion(file:file, version:"16.0.", channel:"Deferred", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7329.1054", channel:"Deferred", channel_version:"1609", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7726.1036", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7927.1024", channel:"Current", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      kb   = "3191863";
      file = "mso99lres.dll";
      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\Office16"
      );
      if (
        hotfix_check_fversion(file:file, version:"16.0.4519.1000", channel:"MSI", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        # hotfix_check_fversion(file:file, version:"16.0.", channel:"Deferred", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7329.1054", channel:"Deferred", channel_version:"1609", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7766.7054", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7927.1024", channel:"Current", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      kb   = "3114375";
      file = "epsimp32.flt";
      path = hotfix_append_path(
        path  : common_path,
        value : "Microsoft Shared\GRPHFLT"
      );
      if (
        hotfix_check_fversion(file:file, version:"2012.1600.4534.1002", channel:"MSI", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        # hotfix_check_fversion(file:file, version:"16.0.", channel:"Deferred", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2012.1600.7329.1054", channel:"Deferred", channel_version:"1609", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2012.1600.7726.1036", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"2012.1600.7927.1024", channel:"Current", channel_product:"Office", path:path, kb:kb, product:prod) == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
}

######################################################################
# Word 2007, 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "3191865";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6768.5000", "kb", "3191836"),
    "14.0", make_array("sp", 2, "version", "14.0.7181.5000", "kb", "3191843"),
    "15.0", make_array("sp", 1, "version", "15.0.4927.1000", "kb", "3178729"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4534.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.6965.2150", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7369.2130", "channel", "Deferred", "channel_version", "1609", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2084", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7967.2161", "channel", "Current", "kb", kb16)
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
  local_var install, installs, path;

  ####################################################################
  # Word Compatibility Pack
  ####################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6768.5000", kb:"3191835", min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# Word Viewer
######################################################################
function perform_viewer_checks()
{
  var word_vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8441.0", "kb", "3191909")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Skype for Business 2016
######################################################################
function perform_skype_checks()
{
  if (int(get_install_count(app_name:"Microsoft Lync")) <= 0)
    return NULL;

  var lync_install, lync_installs, kb, file, prod;

  kb = "3191858";
  file = "Lync.exe";
  prod = "Skype for Business 2016";
  lync_installs = get_installs(app_name:"Microsoft Lync");
  foreach lync_install (lync_installs[1])
  {
    if (lync_install["version"] !~ "^16\.0\.") continue;
    if ("Server" >< lync_install["Product"]) continue;

    # MSI
    if (lync_install['Channel'] == "MSI" || empty_or_null(lync_install['Channel']))
    {
      if (hotfix_check_fversion(file:file, version:"16.0.4534.1000", channel:"MSI", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
    # Deferred
    else if (lync_install['Channel'] == "Deferred")
    {
      if (
        hotfix_check_fversion(file:file, version:"16.0.6965.2150", channel:"Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:file, version:"16.0.7369.2130", channel:"Deferred", channel_version:"1609", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER
      )
        vuln = TRUE;
    }
    else if (lync_install['Channel'] == "First Release for Deferred")
    {
      if (hotfix_check_fversion(file:file, version:"16.0.7766.2084", channel:"First Release for Deferred", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
    else if (lync_install['Channel'] == "Current")
    {
      if (hotfix_check_fversion(file:file, version:"16.0.7967.2161", channel:"Current", channel_product:"Lync", path:lync_install["path"], kb:kb, product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

######################################################################
# Office Web Apps 2010, 2013
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

  ####################################################################
  # Office Web Apps 2010 SP2
  ####################################################################
  if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
  {
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7181.5000", min_version:"14.0.7015.1000", path:path, kb:"3191904", product:"Office Web Apps 2010") == HCF_OLDER)
      vuln = TRUE;
  }

  ####################################################################
  # Office Web Apps 2013 SP1
  ####################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4927.1000", min_version:"15.0.4571.1500", path:path, kb:"3191888", product:"Office Web Apps 2013") == HCF_OLDER)
      vuln = TRUE;
  }
}

######################################################################
# Office Online Server
######################################################################
function perform_oos_checks()
{
  var path;

  if(office_online_server_path)
  {
    path = hotfix_append_path(path:office_online_server_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.7726.1035", min_version:"16.0.6000.0", path:path, kb:"3191915", product:"Office Online Server") == HCF_OLDER)
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
  local_var sps_2016_path, sps_2016_sp, sps_2016_edition;
  local_var installs, install, path;

  installs = get_installs(app_name:"Microsoft SharePoint Server");

  foreach install (installs[1])
  {
    if (install["Product"] == "2016")
    {
      sps_2016_path = install['path'];
      sps_2016_sp = install['SP'];
      sps_2016_edition = install['Edition'];
    }
    else if (install["Product"] == "2013")
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
  }

  ######################################################################
  # SharePoint Server 2016
  ######################################################################
  if (sps_2016_path && sps_2016_sp == "0" && sps_2016_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2016_path, value:"WebServices\ConversionServices");
    if (hotfix_check_fversion(file:"sword.dll", version:"16.0.4534.1000", min_version:"16.0.0.0", path:path, kb:"3191880", product:"Office SharePoint Server 2016") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013 SP1
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1")
  {
    if(sps_2013_edition == "Server")
    {
      # Files under <sps_2013_path>\bin
      path = hotfix_append_path(path:sps_2013_path, value:"Bin");
      if (hotfix_check_fversion(file:"Microsoft.Office.Project.Server.Library.dll", version:"15.0.4873.1000", min_version:"15.0.0.0", path:path, kb:"3191890", product:"Microsoft Project Server 2013") == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4927.1000", min_version:"15.0.0.0", path:path, kb:"3191887", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
       vuln = TRUE;

      # Files under <sps_2013_path>\WebServices\ConversionServices
      path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
      if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4927.1000", min_version:"15.0.0.0", path:path, kb:"3162040", product:"Office SharePoint Server 2013 Word Automation Services") == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"oartserver.dll", version:"15.0.4927.1000", min_version:"15.0.0.0", path:path, kb:"3162069", product:"Office SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"msores.dll", version:"15.0.4913.1000", min_version:"15.0.0.0", path:path, kb:"3172482", product:"SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"htmlutil.dll", version:"15.0.4927.1000", min_version:"15.0.0.0", path:path, kb:"3178633", product:"Office SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;

      if (hotfix_check_fversion(file:"msoserver.dll", version:"15.0.4927.1000", path:path, kb:"3172475", product:"Office SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Visio.Server\v4.0_15.0.0.0__71e9bce111e9429c");
      if (hotfix_check_fversion(file:"Microsoft.Office.Visio.Server.dll", version:"15.0.4797.1000", path:path, kb:"3178638", product:"Office SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.SharePoint.Publishing\v4.0_15.0.0.0__71e9bce111e9429c");
      if (hotfix_check_fversion(file:"Microsoft.SharePoint.Publishing.dll", version:"15.0.4927.1000", path:path, kb:"3191886", product:"Office SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.SharePoint.Client.UserProfiles\v4.0_15.0.0.0__71e9bce111e9429c");
      if (hotfix_check_fversion(file:"Microsoft.SharePoint.Client.UserProfiles.dll", version:"15.0.4745.1000", path:path, kb:"3172532", product:"Office SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:windir, value:"Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.InfoPath.Server\v4.0_15.0.0.0__71e9bce111e9429c");
      if (hotfix_check_fversion(file:"Microsoft.Office.InfoPath.Server.dll", version:"15.0.4873.1000", path:path, kb:"3172536", product:"Office SharePoint Server 2013") == HCF_OLDER)
        vuln = TRUE;
    }
    else if (sps_2013_edition == "Foundation")
    {
      var commonfiles = hotfix_get_commonfilesdir();
      if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

      if(commonfiles) path = hotfix_append_path(path:commonfiles, value:"Microsoft Shared\Web Server Extensions\15\BIN");
      else path = hotfix_append_path(path:sps_2013_path, value:"BIN");
      if (hotfix_check_fversion(file:"onetutil.dll", version:"15.0.4927.1000", min_version:"15.0.0.0", path:path, kb:"3191914", product:"Office Sharepoint Foundation 2013") == HCF_OLDER)
      {
        vuln = TRUE;
        xss = TRUE;
      }

      path = hotfix_append_path(path:sps_2013_path, value:"WebServices\ConversionServices");
      if (hotfix_check_fversion(file:"htmlutil.dll", version:"15.0.4927.1000", min_version:"15.0.0.0", path:path, kb:"3162054", product:"Office Sharepoint Foundation 2013") == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ######################################################################
  # SharePoint Server 2010 SP2
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"WebServices\WordServer\Core");
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7181.5000", path:path, kb:"3191839", product:"Office SharePoint Server 2010 Word Automation Services") == HCF_OLDER)
      vuln = TRUE;
  }
}

perform_office_checks();
perform_word_checks();
perform_comppack_checks();
perform_viewer_checks();
perform_skype_checks();
perform_owa_checks();
perform_oos_checks();
perform_sharepoint_checks();

if (vuln)
{
  # CVE-2017-0255
  if(xss) replace_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
