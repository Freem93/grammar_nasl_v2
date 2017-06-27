#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81757);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id(
    "CVE-2015-0085",
    "CVE-2015-0086",
    "CVE-2015-0097",
    "CVE-2015-1633",
    "CVE-2015-1636"
  );
  script_bugtraq_id(
    72899,
    72911,
    72917,
    72919,
    72922
  );
  script_osvdb_id(
    119365,
    119366,
    119367,
    119368,
    119369
  );
  script_xref(name:"MSFT", value:"MS15-022");
  script_xref(name:"IAVA", value:"2015-A-0052");

  script_name(english:"MS15-022: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3038999)");
  script_summary(english:"Checks the Office, SharePoint, and OWA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Office
Compatibility Pack, Microsoft Word Viewer, Microsoft Excel Viewer,
SharePoint Server, or Microsoft Office Web Apps that is affected by
multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist due
    to incorrectly handling objects and rich text format
    files in memory. A remote attacker can exploit these
    vulnerabilities by convincing a user to open a specially
    crafted file using the affected software, resulting in
    execution of arbitrary code in the context of the
    current user. (CVE-2015-0085, CVE-2015-0086,
    CVE-2015-0097)

  - Multiple cross-site scripting vulnerabilities exist due
    to improperly sanitized requests to affected SharePoint
    servers. An authenticated attacker, via a specially
    crafted request, can exploit these vulnerabilities to
    execute script code in the security context of the
    current user. (CVE-2015-1633, CVE-2015-1636)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-022");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
Office Compatibility Pack, Microsoft Word Viewer, Microsoft Excel
Viewer, SharePoint Server, and Office Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

global_var bulletin, vuln;

function get_ver()
{
  local_var fh, path, rc, share, ver;

  path = _FCT_ANON_ARGS[0];

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  rc = NetUseAdd(share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  ver = NULL;
  path = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:'\\1\\');

  fh = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    ver = join(ver, sep:".");
    CloseFile(handle:fh);
  }

  NetUseDel(close:FALSE);

  return ver;
}

function check_vuln(fix, kb, name, path, ver)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

bulletin = 'MS15-022';
kbs = make_list(
  2984939, # Office 2007
  2956103, # Excel 2007
  2899580, # PowerPoint 2007
  2956109, # Word 2007
  2956076, # Office 2010
  2956138, # Office 2010
  2883100, # Office 2010
  2889839, # Office 2010 (oart)
  2956142, # Excel 2010
  2920812, # PowerPoint 2010
  2956139, # Word 2010
  2956151, # Office 2013
  2956163, # Word 2013
  2956188, # Word Viewer
  2956189, # Excel Viewer
  2956107, # Office Compat Pack (wordconv)
  2956106, # Office Compat Pack (xlconv)
  2956136, # SharePoint 2010 Word Automation Services
  2956143, # SharePoint 2013 Excel Services
  2920731, # SharePoint 2013 Word Automation Services
  2956069, # Office Web Apps 2010
  2956158, # Office Web Apps 2013
  2881068, # SharePoint Server 2007
  2956208, # SharePoint Server 2010
  2956175, # SharePoint Server 2013
  2956183, # SharePoint Server 2013
  2760508, # SharePoint Server 2013
  2956180,
  2956153,
  2760554,
  2880473,
  2737989,
  2881078,
  2956181,
  2760361
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the path information for SharePoint Server 2007
sps_2007_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\12.0\InstallPath"
);

# Get the path information for SharePoint Services 3.0
sps_30_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0\Location"
);

# Get path information for SharePoint Server 2010.
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

# Get the path information for SharePoint Foundation 2010
spf_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\Location"
);

# Get the path information for SharePoint Server 2013
sps_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\15.0\InstallPath"
);

# Get the path information for SharePoint Foundation 2013
spf_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWRAE\Microsoft\Shared Tools\Web Server Extensions\15.0\Location"
);

owa_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.WacServer\InstallLocation"
);

# Close connection to registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);
# Get path information for Office Web Apps.
owa_2010_path = sps_2010_path;

######################################################################
# Office Web Apps 2010 SP1 / SP2
######################################################################
if (owa_2010_path)
{
  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2956070",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix  : "14.0.7145.5000"
  );
}

######################################################################
# Office Web Apps 2013 SP1 / SP2
######################################################################
if (owa_2013_path)
{
  check_vuln(
    name : "Office Web Apps 2013",
    kb   : "2956158",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Web.Apps.Environment.WacServer\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.Web.Apps.Environment.WacServer.dll",
    fix : "15.0.4693.1000"
  );
}
######################################################################
# SharePoint Server 2007 SP3
######################################################################
if (sps_2007_path && sps_30_path)
{
  check_vuln(
    name : "Office SharePoint Server 2007",
    kb   : "2881068",
    path : sps_30_path + "\BIN\offparser.dll",
    fix  : "12.0.6717.5000"
  );
}

######################################################################
# SharePoint Server 2010 SP2
######################################################################
if (sps_2010_path)
{
  check_vuln(
    name : "Office SharePoint Server 2010",
    kb   : "2956136",
    path : sps_2010_path + "WebServices\WordServer\Core\sword.dll",
    fix  : "14.0.7145.5000"
  );
}

######################################################################
# SharePoint Foundation 2010
######################################################################
if (spf_2010_path)
{
  path = spf_2010_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^14\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2956208",
      path : path,
      ver  : ver,
      fix  : "14.0.7145.5000"
    );
  }
}

######################################################################
# SharePoint Server 2013 SP2
######################################################################
if (sps_2013_path)
{
  check_vuln(
    name : "Office SharePoint Server 2013 Excel Services",
    kb   : "2956143",
    path : sps_2013_path + "Bin\xlsrv.dll",
    fix  : "15.0.4701.1000"
  );
  
  check_vuln(
    name : "SharePoint Server 2013 Word Automation Services",
    kb   : "2920731",
    path : sps_2013_path + "WebServices\ConversionServices\sword.dll",
    fix  : "15.0.4701.1000"
  );

  check_vuln(
    name : "SharePoint Server 2013 (arcsrvloc)",
    kb   : "2956180",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Access.Server\v4.0.15.0.0.0__71e9bce111e9429c\Microsoft.Office.Access.Server.dll",
    fix  : "15.0.4525.1000"
  );

  check_vuln(
    name : "SharePoint Server 2013 (coreserverloc)",
    kb   : "2956153",
    path : sps_2013_path + "Bin\MSSCPI.DLL",
    fix  : "15.0.4681.1000"
  );
  
  check_vuln(
    name : "SharePoint Server 2013 (eduloc)",
    kb   : "2760554",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.SharePoint.Client.UserProfiles\v4.0.15.0.0.0__71e9bce111e9429c\Microsoft.SharePoint.Client.UserProfiles.dll",
    fix  : "15.0.4567.1000"
  );
  
  check_vuln(
    name : "SharePoint Server 2013 (ifsloc)",
    kb   : "2880473",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.InfoPath.Server\v4.0.15.0.0.0__71e9bce111e9429c\Microsoft.Office.InfoPath.Server.dll",
    fix  : "15.0.4701.1000"
  );

  check_vuln(
    name : "SharePoint Server 2013 (lpsrvloc)",
    kb   : "2737989",
    path : sps_2013_path + "WebServices\ConversionServices\oartserver.dll",
    fix  : "15.0.4701.1000"
  );
  
  check_vuln(
    name : "SharePoint Server 2013 (ppsmaloc)",
    kb   : "2881078",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.PerformancePoint.Scorecards.Server\v4.0.15.0.0.0__71e9bce111e9429c\Microsoft.PerformancePoint.Scorecards.Server.dll",
    fix  : "15.0.4701.1000"
  );
  
  check_vuln(
    name : "SharePoint Server 2013 (vsrvloc)",
    kb   : "2956181",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Viso.Server\v4.0.15.0.0.0__71e9bce111e9429c\Microsoft.Office.Visio.Server.dll",
    fix  : "15.0.4659.1000"
  );
  
  check_vuln(
    name : "SharePoint Server 2013 (wasrvloc)",
    kb   : "2760361",
    path : sps_2013_path + "WebServices\ConversionServices\msores.dll",
    fix  : "15.0.4697.1000"
  );
}

######################################################################
# SharePoint Foundation 2013
######################################################################
if (spf_2013_path)
{
  check_vuln(
    name : "SharePoint Foundation 2013",
    kb   : "2956175",
    path : spf_2013_path + "Bin\CsiSrv.dll",
    fix  : "15.0.4699.1000"
  );

  check_vuln(
    name : "SharePoint Foundation 2013 (wssloc)",
    kb   : "2956183",
    path : spf_2013_path + "wsssetup.dll",
    fix  : "15.0.4701.1000"
  );

  if (sps_2013_path)
  {
    check_vuln(
      name : "SharePoint Foundation 2013 (smsloc)",
      kb   : "2760508",
      path : sps_2013_path + "\WebServices\ConversionServices\IGXServer.DLL",
      fix  : "15.0.4699.1000"
    );
  }
}


# Excel
kb = "";
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    path = installs[install];
    info = "";

    # Excel 2010
    if (version =~ "^14\." && ver_compare(ver:version, fix:'14.0.7145.5001') < 0)
    {
      office_sp = get_kb_item('SMB/Office/2010/SP');
      if (!isnull(office_sp) && office_sp == 2)
      {
        info =
          '\n  Product           : Excel 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 14.0.7145.5001\n';
        kb = '2956142';
      }
    }

    # Excel 2007
    if (version =~ "^12\." && ver_compare(ver:version, fix:'12.0.6718.5000') < 0)
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 3))
      {
        info =
          '\n  Product           : Excel 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6718.5000\n';
        kb = '2956103';
      }
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

# PowerPoint
kb = "";
installs = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/PowerPoint/' - '/ProductPath';
    path = installs[install];
    info = "";

    # PowerPoint 2010 SP2
    if (version =~ "^14\." && ver_compare(ver:version, fix:'14.0.7145.5001') < 0)
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && (office_sp == 2))
      {
        info =
          '\n  Product           : PowerPoint 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 14.0.7145.5001' + '\n';
        kb = "2920812";
      }
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

# Word
kb = "";
installs = get_kb_list("SMB/Office/Word/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Word/' - '/ProductPath';
    path = installs[install];
    info = "";

    # Word 2013
    if (version =~ "^15\." && ver_compare(ver:version, fix:'15.0.4701.1001') < 0)
    {
      office_sp = get_kb_item("SMB/Office/2013/SP");
      if (!isnull(office_sp) && (office_sp <= 1))
      {
        info =
          '\n  Product           : Word 2013' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 15.0.4701.1001' + '\n';
        kb = "2956163";
      }
    }

    # Word 2010 SP2
    if (version =~ "^14\." && ver_compare(ver:version, fix:'14.0.7145.5001') < 0)
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && (office_sp == 2))
      {
        info =
          '\n  Product           : Word 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 14.0.7145.5001' + '\n';
        kb = "2956139";
      }
    }

    # Word 2007 SP3
    if (version =~ "^12\." && ver_compare(ver:version, fix:'12.0.6718.5000') < 0)
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2007 SP3' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6718.5000' + '\n';
        kb = "2956109";
      }
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
    }
  }
}

# Word Viewer
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/WordViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    if (ver_compare(ver:version, fix:'11.0.8416.0') < 0)
    {
      info =
        '\n  Product           : Word Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8416.0' + '\n';
      kb = "2956188";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
      break;
    }
  }
}

# Excel Viewer
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    if (ver_compare(ver:version, fix:'12.0.6717.5000') < 0)
    {
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6717.5000' + '\n';
      kb = "2956189";
    }

    if (info)
    {
      hotfix_add_report(info, bulletin:bulletin, kb:kb);
      vuln = TRUE;
      break;
    }
  }
}

# Ensure Office is installed
office_vers = hotfix_check_office_version();
if (!isnull(office_vers))
{
  # Ensure we can get common files directory
  commonfiles = hotfix_get_officecommonfilesdir(officever:"14.0");
  if (commonfiles)
  {
    # Ensure share is accessible
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:commonfiles);
    if (is_accessible_share(share:share))
    {
      # Office 2013
      if (office_vers["15.0"])
      {
        office_sp = get_kb_item("SMB/Office/2013/SP");
        if (!isnull(office_sp) && office_sp <= 1)
        {
          path = commonfiles + "\Microsoft Shared\Office15";
          old_report = hotfix_get_report();
          check_file = "Mso.dll";
          
          if (hotfix_check_fversion(path:path, file:check_file, version:"15.0.4701.1000", min_version:"15.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            kb_name = str_replace(find:"//", replace:"/", string:kb_name);
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2013' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 15.0.4701.1000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2956151");
            vuln = TRUE;
          }
        }
      }
      # Office 2010
      if (office_vers["14.0"])
      {
        office_sp = get_kb_item("SMB/Office/2010/SP");
        if (!isnull(office_sp) && office_sp == 2)
        {
          
          path = commonfiles + "\Microsoft Shared\Office14";
          old_report = hotfix_get_report();
          check_file = "Mso.dll";

          if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7145.5000", min_version:"14.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            kb_name = str_replace(find:"//", replace:"/", string:kb_name);
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2010' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 14.0.7145.5000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2956076");
            vuln = TRUE;
          }
          
          old_report = hotfix_get_report();
          check_file = "Oart.dll";
          if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7134.5000", min_version:"14.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            kb_name = str_replace(find:"//", replace:"/", string:kb_name);
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2010' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 14.0.7134.5000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2883100");
            vuln = TRUE;
          }
          
          old_report = hotfix_get_report();
          check_file = "Oartconv.dll";
          if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7134.5000", min_version:"14.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            kb_name = str_replace(find:"//", replace:"/", string:kb_name);
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2010' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 14.0.7134.5000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2889839");
            vuln = TRUE;
          }

          path = get_kb_item("SMB/Office/Word/14.0/Path");
          if (!path) path = get_kb_item("SMB/Office/Excel/14.0/Path");
          if (!path) path = get_kb_item("SMB/Office/PowerPoint/14.0/Path");
          if (path)
          {
            old_report = hotfix_get_report();
            check_file = "Wwlib.dll";

            if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7145.5000", min_version:"14.0.0.0") == HCF_OLDER)
            {
              file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
              kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
              kb_name = str_replace(find:"//", replace:"/", string:kb_name);
              version = get_kb_item(kb_name);

              info =
                '\n  Product           : Microsoft Office 2010' +
                '\n  File              : ' + path + '\\' + check_file +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 14.0.7145.5000' + '\n';

              hcf_report = '';
              hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2956138");
              vuln = TRUE;
            }
          }
        }
      }

      # Office 2007 SP3
      if (office_vers["12.0"])
      {
        office_sp = get_kb_item("SMB/Office/2007/SP");
        if (!isnull(office_sp) && office_sp == 3)
        {
          path = commonfiles + "\Microsoft Shared\Office12";
          old_report = hotfix_get_report();
          check_file = "Mso.dll";

          if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6718.5000", min_version:"12.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/" + tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            version = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2007 SP3' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + version +
              '\n  Fixed version     : 12.0.6718.5000\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2984939");
            vuln = TRUE;
          }

          path = get_kb_item("SMB/Office/PowerPoint/14.0/Path");
          if (!empty_or_null(path))
          {
            old_report = hotfix_get_report();
            check_file = "ppcore.dll";

            if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6718.5000", min_version:"12.0.0.0") == HCF_OLDER)
            {
              file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
              kb_name = "SMB/FileVersions/" + tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
              version = get_kb_item(kb_name);

              info =
                '\n  Product           : Microsoft PowerPoint 2007 SP3' +
                '\n  File              : ' + path + '\\' + check_file +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 12.0.6718.5000\n';
              hcf_report = '';
              hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2899580");
              vuln = TRUE;
            }
          }
        }
      }
    }
  }
}

version = '';
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/WordCnv/' - '/ProductPath';
    path = installs[install];

    if (!isnull(path))
    {
      share = hotfix_path2share(path:path);
      if (!is_accessible_share(share:share))
        audit(AUDIT_SHARE_FAIL, share);

      path = path - '\\Wordconv.exe';

      old_report = hotfix_get_report();
      check_file = "wordcnv.dll";

      if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6717.5000", min_version:"12.0.0.0") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        kb_name = ereg_replace(pattern:"//"+check_file, replace:"/"+check_file, string:kb_name);
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
          '\n  File              : ' + path + '\\' + check_file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6717.5000' + '\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2956107");
        vuln = TRUE;
      }
    }
  }
}

version = '';
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    if (ver_compare(ver:version, fix:'12.0.6717.5000') < 0)
    {
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6717.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2956106");
      vuln = TRUE;
    }
  }
}

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
