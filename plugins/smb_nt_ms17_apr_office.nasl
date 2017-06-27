#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99314);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/05/25 21:43:15 $");

  script_cve_id(
    "CVE-2017-0106",
    "CVE-2017-0194",
    "CVE-2017-0195",
    "CVE-2017-0197",
    "CVE-2017-0199",
    "CVE-2017-0204",
    "CVE-2017-0207",
    "CVE-2017-2605"
  );
  script_bugtraq_id(
    95961,
    97411,
    97413,
    97417,
    97436,
    97458,
    97463,
    97498
  );
  script_osvdb_id(
    155336,
    155357,
    155358,
    155359,
    155363,
    155366,
    155379,
    155382
  );
  script_xref(name:"IAVA", value:"2017-A-0101");
  script_xref(name:"IAVA", value:"2017-A-0102");
  script_xref(name:"IAVA", value:"2017-A-0104");
  script_xref(name:"IAVA", value:"2017-A-0105");
  script_xref(name:"MSKB", value:"2589382");
  script_xref(name:"MSKB", value:"3101522");
  script_xref(name:"MSKB", value:"3118388");
  script_xref(name:"MSKB", value:"3127890");
  script_xref(name:"MSKB", value:"3127895");
  script_xref(name:"MSKB", value:"3141529");
  script_xref(name:"MSKB", value:"3141538");
  script_xref(name:"MSKB", value:"3172519");
  script_xref(name:"MSKB", value:"3178664");
  script_xref(name:"MSKB", value:"3178702");
  script_xref(name:"MSKB", value:"3178703");
  script_xref(name:"MSKB", value:"3178710");
  script_xref(name:"MSKB", value:"3178724");
  script_xref(name:"MSKB", value:"3178725");
  script_xref(name:"MSKB", value:"3191827");
  script_xref(name:"MSKB", value:"3191829");
  script_xref(name:"MSKB", value:"3191830");
  script_xref(name:"MSKB", value:"3191840");
  script_xref(name:"MSKB", value:"3191845");
  script_xref(name:"MSKB", value:"3191847");

  script_name(english:"Security Update for Microsoft Office Products (April 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application, Office Web Apps, or SharePoint
Server installed on the remote Windows host is missing a security
update. It is, therefore, affected by multiple vulnerabilities :

  - An arbitrary code execution vulnerability exists in
    Microsoft Outlook due to improper parsing of email
    messages. An unauthenticated, remote attacker can
    exploit this, via a specially crafted email message, to
    execute arbitrary code. (CVE-2017-0106)

  - An information disclosure vulnerability exists in
    Microsoft Office due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted
    Excel file, to disclose the contents of memory.
    (CVE-2017-0194)

  - A cross-site scripting (XSS) vulnerability exists in
    Office Web Apps Server due to improper validation of
    input before returning it to users. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-0195)

  - An arbitrary code execution vulnerability exists in
    Microsoft Office due to improper validation of input
    before loading dynamic link library (DLL) files. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted Office
    document, to execute arbitrary code. (CVE-2017-0197)

  - An arbitrary code execution vulnerability exists in
    Microsoft Office and Windows WordPad due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to open a specially crafted file, to execute arbitrary
    code. (CVE-2017-0199)

  - A security feature bypass vulnerability exists in
    Microsoft Office due to improper parsing of file
    formats. An unauthenticated, remote attacker can exploit
    this, by convincing a user into opening a specially
    crafted file, to bypass security features.
    (CVE-2017-0204)

  - A spoofing vulnerability in Microsoft Outlook due to
    improper validation of input passed via HTML tags. An
    unauthenticated, remote attacker can exploit this, by
    sending an email with specific HTML tags, to display a
    malicious authentication prompt and gain access to a
    user's authentication information or login credentials.
    (CVE-2017-0207)

  - An unspecified flaw exists in Microsoft Office in the
    Encapsulated PostScript (EPS) filter that allows an
    attacker to have an unspecified impact. (CVE-2017-2605)");
  script_set_attribute(attribute:"see_also",value:"https://portal.msrc.microsoft.com/en-us/security-guidance/summary");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, and 2016; Microsoft Excel 2007 and 2010; Microsoft OneNote
2007 and 2010; Microsoft Outlook 2007, 2010, 2013, and 2016; Microsoft
Office Compatibility Pack; Excel Services on Microsoft SharePoint
Server 2010 and 2013; Microsoft Excel Web App 2010; Microsoft Office
Web Apps Server 2010 and 2013; and Office Online Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Office Word Malicious Hta Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies(
    "office_installed.nasl",
    "onenote_installed.nbin",
    "microsoft_sharepoint_installed.nbin",
    "microsoft_owa_installed.nbin",
    "microsoft_office_compatibility_pack_installed.nbin",
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

bulletin = "MS17-04";
kbs = make_list(
  '2589382', # OneNote 2010 SP2
  '3101522', # Excel Web App 2010 SP2
  '3118388', # Outlook 2010 SP2
  '3127890', # Outlook 2007 SP3
  '3127895', # Office Online Server
  '3141529', # Office 2007 SP3
  '3141538', # Office 2010 SP2
  '3172519', # Outlook 2013 SP1
  '3178664', # Outlook 2016
  '3178702', # Office 2016
  '3178703', # Office 2016
  '3178710', # Office 2013 SP1
  '3178724', # Excel Services on SharePoint Server 2013
  '3178725', # Office Web Apps Server 2013 SP1
  '3191827', # Excel 2007 SP3
  '3191829', # OneNote 2007 SP3
  '3191830', # Office Compatibility Pack SP2
  '3191840', # Excel Services on SharePoint Server 2010
  '3191845', # Office Web Apps 2010 SP2
  '3191847'  # Excel 2010 SP2
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
  local_var office_vers, office_sp, path, prod;
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
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6766.5000", path:path, kb:"3141529", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ####################################################################
  # Office 2010 SP2 Checks
  ####################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      path = hotfix_append_path(
        path  : hotfix_get_officecommonfilesdir(officever:"14.0"),
        value : "Microsoft Shared\Office14"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7180.5000", path:path, kb:"3141538", product:prod) == HCF_OLDER)
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
      path = hotfix_append_path(
        path  : hotfix_get_officecommonfilesdir(officever:"15.0"),
        value : "Microsoft Shared\Office15"
      );
      if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4919.1000", path:path, kb:"3178710", product:prod) == HCF_OLDER)
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
      path = hotfix_append_path(
        path:hotfix_get_officecommonfilesdir(officever:"16.0"),
        value:"Microsoft Shared\Office16"
      );
      if (
        hotfix_check_fversion(file:"mso.dll", version:"16.0.4522.1002", channel:"MSI", channel_product:"Office", path:path, kb:"3178702", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll", version:"16.0.6925.1057", channel:"Deferred", channel_product:"Office", path:path, kb:"3178702", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll", version:"16.0.7329.1051", channel:"Deferred", channel_version:"1609", channel_product:"Office", path:path, kb:"3178702", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll", version:"16.0.7726.1030", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:"3178702", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll", version:"16.0.7830.1021", channel:"Current", channel_product:"Office", path:path, kb:"3178702", product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      if(
        hotfix_check_fversion(file:"mso30win32client.dll", version:"16.0.4522.1000", channel:"MSI", channel_product:"Office", path:path, kb:"3178703", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso30win32client.dll", version:"16.0.6925.1057", channel:"Deferred", channel_product:"Office", path:path, kb:"3178703", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso30win32client.dll", version:"16.0.7329.1051", channel:"Deferred", channel_version:"1609", channel_product:"Office", path:path, kb:"3178703", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso30win32client.dll", version:"16.0.7726.1030", channel:"First Release for Deferred", channel_product:"Office", path:path, kb:"3178703", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso30win32client.dll", version:"16.0.7830.1021", channel:"Current", channel_product:"Office", path:path, kb:"3178703", product:prod) == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
}

######################################################################
# Excel 2007, 2010
######################################################################
function perform_excel_checks()
{
  local_var excel_checks;

  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6766.5000", "kb", "3191827"),
    "14.0", make_array("sp", 2, "version", "14.0.7180.5000", "kb", "3191847")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Outlook 2007, 2010, 2013, 2016
######################################################################
function perform_outlook_checks()
{
  local_var outlook_checks, kb16;

  kb16 = "3178664";
  outlook_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6767.5000", "kb", "3127890"),
    "14.0", make_array("sp", 2, "version", "14.0.7180.5001", "kb", "3118388"),
    "15.0", make_array("sp", 1, "version", "15.0.4919.1001", "kb", "3172519"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4522.1001", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.6965.2145", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7369.2127", "channel", "Deferred", "channel_version", "1609", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2076", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7870.2038", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:outlook_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# OneNote 2007, 2010
######################################################################
function perform_onenote_checks()
{
  var install, installs, prod, path;

  installs = get_installs(app_name:'Microsoft OneNote');
  if(!empty_or_null(installs))
  {
    foreach install (installs[1])
    {
      ################################################################
      # OneNote 2007 SP3 Checks
      ################################################################
      if (install["product"] == "2007" && install["sp"] == 3)
      {
        prod = "Microsoft OneNote 2007 SP3";
        path = tolower(install["path"]);
        path -= "onenote.exe";
        if (hotfix_check_fversion(file:"onenotesyncpc.dll", version:"12.0.6765.5000", path:path, kb:"3191829", product:prod) == HCF_OLDER)
          vuln = TRUE;
      }

      ################################################################
      # OneNote 2010 SP2 Checks
      ################################################################
      else if (install["product"] == "2010" && install["sp"] == 2)
      {
        prod = "Microsoft OneNote 2010 SP2";
        path = tolower(install["path"]);
        path -= "onenote.exe";
        if (hotfix_check_fversion(file:"onenotesyncpc.dll", version:"14.0.7180.5000", path:path, kb:"2589382", product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    }
  }
}


######################################################################
# Compatibility Pack
######################################################################
function perform_comppack_checks()
{
  local_var excel_compat_checks;

  ####################################################################
  # Excel Compatibility Pack
  ####################################################################
  excel_compat_checks = make_array(
    "12.0", make_array("version", "12.0.6766.5000", "kb", "3191830")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:excel_compat_checks, bulletin:bulletin))
    vuln = TRUE;
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
    if (hotfix_check_fversion(file:"sword.dll", version:"14.0.7180.5000", min_version:"14.0.7015.1000", path:path, kb:"3191845", product:"Office Web Apps 2010") == HCF_OLDER)
    {
      vuln = TRUE;
      xss  = TRUE;
    }

    # Excel Web App
    path = hotfix_append_path(path:owa_2010_path, value:"14.0\Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7180.5000", path:path, kb:"3101522", product:"Excel Web App 2010") == HCF_OLDER)
    {
      vuln = TRUE;
      xss  = TRUE;
    }
  }

  ####################################################################
  # Office Web Apps 2013 SP1
  ####################################################################
  if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
  {
    path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
    if (hotfix_check_fversion(file:"sword.dll", version:"15.0.4919.1000", min_version:"15.0.4571.1500", path:path, kb:"3178725", product:"Office Web Apps 2013") == HCF_OLDER)
    {
      vuln = TRUE;
      xss  = TRUE;
    }
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
    path = hotfix_append_path(path:office_online_server_path, value:"UlsController");
    if (hotfix_check_fversion(file:"uls.dll", version:"16.0.7329.1048", min_version:"16.0.6000.0", path:path, kb:"3127895", product:"Office Online Server") == HCF_OLDER)
    {
      vuln = TRUE;
      xss  = TRUE;
    }
  }
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2010_path, sps_2010_sp, sps_2010_edition;
  local_var sps_2013_path, sps_2013_sp, sps_2013_edition;
  local_var installs, install, path;

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
  }

  ######################################################################
  # SharePoint Server 2013 SP1 - Excel Services
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4919.1000", min_version:"15.0.0.0", path:path, kb:"3178724", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
    {
      vuln = TRUE;
      xss  = TRUE;
    }
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Word Automation Services / Excel Services
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7180.5000", path:path, kb:"3191840", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
    {
      vuln = TRUE;
      xss  = TRUE;
    }
  }
}

perform_office_checks();
perform_excel_checks();
perform_outlook_checks();
perform_onenote_checks();
perform_comppack_checks();
perform_owa_checks();
perform_oos_checks();
perform_sharepoint_checks();

if (vuln)
{
  # CVE-2017-0195
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
