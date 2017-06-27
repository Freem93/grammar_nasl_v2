#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73413);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2014-1757", "CVE-2014-1758", "CVE-2014-1761");
  script_bugtraq_id(66385, 66614, 66629);
  script_osvdb_id(104895, 105532, 105533);
  script_xref(name:"CERT", value:"882841");
  script_xref(name:"IAVA", value:"2014-A-0049");
  script_xref(name:"MSFT", value:"MS14-017");

  script_name(english:"MS14-017: Vulnerabilities in Microsoft Word and Office Web Apps Could Allow Remote Code Execution (2949660)");
  script_summary(english:"Checks Word / Office Web Apps version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple memory corruption
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Microsoft
Word, Office Compatibility Pack, Microsoft Word Viewer, SharePoint
Server, or Microsoft Office Web Apps that is affected by one or more
unspecified memory corruption vulnerabilities. By tricking a user into
opening a specially crafted file, it may be possible for a remote
attacker to take complete control of the system or execute arbitrary
code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-017");
  script_set_attribute(attribute:"see_also", value:"http://securitytracker.com/id?1029948");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2003, 2007, 2010,
2013, Office Compatibility Pack, Microsoft Word Viewer, SharePoint
Server, and Office Web Apps.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS14-017 Microsoft Word RTF Object Confusion');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS14-017';
kbs = make_list(
  2863910, # Word 2013
  2878220, # Word Automation Services in SharePoint Server 2010
  2878221, # Word Web App
  2878236, # Office Compatibility Pack
  2878237, # Word 2007
  2863907, # Word Automation Services in SharePoint Server 2013
  2878303, # Word 2003
  2878304, # Microsoft Word Viewer
  2878219, # Office Web Apps Server 2013
  2863919, # Microsoft Office 2010
  2863926  # Word 2010 SP1 and SP2
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get path information for SharePoint Server 2010.
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

# Get the path information for SharePoint Server 2013
sps_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\15.0\InstallPath"
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
    kb   : "2878221",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix  : "14.0.7121.5004"
  );
}

######################################################################
# Office Web Apps 2013
######################################################################
if (owa_2013_path)
{
  check_vuln(
    name : "Office Web Apps 2013",
    kb   : "2878219",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Web.Apps.Environment.WacServer\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.Web.Apps.Environment.WacServer.dll",
    fix  : "15.0.4569.1503"
  );
}

######################################################################
# SharePoint Server 2010 SP1 / SP2
######################################################################
if (sps_2010_path)
{
  check_vuln(
    name : "Office SharePoint Server 2010",
    kb   : "2878220",
    path : sps_2010_path + "WebServices\WordServer\Core\sword.dll",
    fix  : "14.0.7121.5004"
  );
}

######################################################################
# SharePoint Server 2013
######################################################################
if (sps_2013_path)
{
  check_vuln(
    name : "Office SharePoint Server 2013",
    kb   : "2863907",
    path : sps_2013_path + "WebServices\ConversionServices\sword.dll",
    fix  : "15.0.4605.1001"
  );
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

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    if(ver[0] == 15 && ver[1] == 0)
    {
      ######################################################################
      # Office 2013 PIA Check
      ######################################################################
      # Word 2013
      if (
        ver[2] < 4605 ||
        (ver[2] == 4605 && ver[3] < 1001)
      )
      {
        office_sp = get_kb_item("SMB/Office/2013/SP");
        if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
        {
          info =
            '\n  Product           : Word 2013' +
            '\n  File              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 15.0.4605.1001' + '\n';
          kb = "2863910";
        }
      }
    }

    # Word 2010 SP1 and SP2
    if (
      ver[0] == 14 && ver[1] == 0 &&
      (
        ver[2] < 7121 ||
        (ver[2] == 7121 && ver[3] < 5004)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        info =
          '\n  Product           : Word 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 14.0.7121.5004' + '\n';
        kb = "2863926";
      }
    }

    # Word 2007 SP3
    if (
      ver[0] == 12 && ver[1] == 0 &&
      (
        ver[2] < 6695 ||
        (ver[2] == 6695 && ver[3] < 5000)
      )
    )
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2007 SP3' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6695.5000' + '\n';
        kb = "2878237";
      }
    }

    # Word 2003 SP3
    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8411)
    {
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        info =
          '\n  Product           : Word 2003' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 11.0.8411.0' + '\n';
        kb = "2878303";
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

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

    if (ver[0] == 11 && ver[1] == 0 && ver[2] < 8411)
    {
      info =
        '\n  Product           : Word Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 11.0.8411.0' + '\n';
      kb = "2878304";
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
      # Office 2010
      if (office_vers["14.0"])
      {
        office_sp = get_kb_item("SMB/Office/2010/SP");
        if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
        {
          path = get_kb_item("SMB/Office/Word/14.0/Path");
          if (path)
          {
            old_report = hotfix_get_report();
            check_file = "Wwlib.dll";

            if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7121.5004", min_version:"14.0.0.0") == HCF_OLDER)
            {
              file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
              kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
              version = get_kb_item(kb_name);

              info =
                '\n  Product           : Microsoft Office 2010' +
                '\n  File              : ' + path + '\\' + check_file +
                '\n  Installed version : ' + version +
                '\n  Fixed version     : 14.0.7121.5004' + '\n';

              hcf_report = '';
              hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2863919");
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

      if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6695.5000", min_version:"12.0.0.0") == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        kb_name = ereg_replace(pattern:"//"+check_file, replace:"/"+check_file, string:kb_name);
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : Microsoft Office Compatibility Pack for Word, Excel, and PowerPoint 2007 File Formats' +
          '\n  File              : ' + path + '\\' + check_file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6695.5000' + '\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2878236");
        vuln = TRUE;
      }
    }
  }
}

if (!version)
{
  # Additional check if registry key is missing
  path = hotfix_get_officecommonfilesdir(officever:"12.0") + "\Microsoft Office\Office12";

  kb = "2878236";
  if (
    hotfix_is_vulnerable(file:"wordcnv.dll", version:"12.0.6695.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb)
  ) vuln = TRUE;
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
