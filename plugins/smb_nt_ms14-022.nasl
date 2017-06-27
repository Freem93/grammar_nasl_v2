#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73981);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-1754", "CVE-2014-1813", "CVE-2014-0251");
  script_bugtraq_id(67283, 67288, 67290);
  script_osvdb_id(106891, 106892, 106893);
  script_xref(name:"MSFT", value:"MS14-022");
  script_xref(name:"IAVA", value:"2014-A-0074");

  script_name(english:"MS14-022: Vulnerabilities in Microsoft SharePoint Server Could Allow Remote Code Execution (2952166)");
  script_summary(english:"Checks SharePoint / Office Web Apps version.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The versions of Office SharePoint Server, Office Web Apps, SharePoint
Client Components SDK, or SharePoint Designer installed on the remote
host are affected by multiple vulnerabilities :

  - A code execution vulnerability exists in Microsoft
    SharePoint Server. (CVE-2014-0251)

  - A cross-site scripting vulnerability exists in
    Microsoft SharePoint Server. (CVE-2014-1754)

  - A code execution vulnerability exists in Microsoft
    Web Applications. (CVE-2014-1813)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-022");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2007,
SharePoint Server 2010, SharePoint Server 2013, and Office Web Apps
2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_designer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

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

bulletin = "MS14-022";
kbs = make_list(
  2596763,
  2596810,
  2596861,
  2596902,
  2752096,
  2760236,
  2810069,
  2837588,
  2837598,
  2837616,
  2863829,
  2863836,
  2863854,
  2863856,
  2863863,
  2863922,
  2880453,
  2880536
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated", exit_code:1);

# Connect to the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the path information for SharePoint Server 2007
sps_2007_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\12.0\InstallPath"
);

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

# Get the path information for SharePoint Service 3.0
sps_30_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0\Location"
);

# Get path information for SharePoint Foundation 2010.
spf_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\Location"
);

# Get the path information for SharePoint Foundation 2013
spf_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\15.0\Location"
);

# Determine if SharePoint Server 2013 Client Components SDK is installed
spc_sdk_2013 = FALSE;
display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (display_names)
{
  foreach item (keys(display_names))
  {
    if ('SharePoint Client Components' >< display_names[item])
    {
      item = item - 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/';
      item = item - '/DisplayName';
      ver = get_kb_item('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/' + item + '/DisplayVersion');
      if (ver =~ '^15\\.')
        spc_sdk_2013 = TRUE;
    }
  }
}

# Determine bitness of SharePoint Designer
if (get_kb_list("SMB/Office/SharePointDesigner/*/ProductPath"))
{
  spd_arches = make_array('12.0', 'x86', '14.0', 'x86', '15.0', 'x86');
  if (arch == 'x64')
  {
    foreach ver (keys(spd_arches))
    {
      if (get_registry_value(handle:hklm, item:"SOFTWARE\Wow6432Node\Microsoft\Office" + ver + "\SharePoint Designer\InstallRoot\Path"))
        spd_arches[ver] = 'x64';
    }
  }
}

# Close connection to registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir))
  exit(1, "Failed to determine the location of %windir%.");

# Get path information for Common Files.
commonprogramfiles = hotfix_get_commonfilesdir();
if (isnull(commonprogramfiles))
  exit(1, "Failed to determine the location of %commonprogramfiles%.");

# Get path information for Office Web Apps.
owa_2010_path = sps_2010_path;

######################################################################
# SharePoint Server 2007 SP3
#
# [KB2837616] owssvr.dll: 12.0.6690.5000
# [KB2596902] Microsoft.Office.Server.Conversions.Launcher.exe: 12.0.6690.5000
# [KB2596763] Microsoft.Office.Policy.dll: 12.0.6690.5000
######################################################################
if (sps_2007_path)
{
  name = "Office SharePoint Server 2007";

  check_vuln(
    name : name,
    kb   : "2837616",
    path : sps_30_path + "\ISAPI\owssvr.dll",
    fix  : "12.0.6690.5000"
  );

  check_vuln(
    name : name,
    kb   : "2596902",
    path : sps_2007_path + "\Bin\Microsoft.Office.Server.Conversions.Launcher.exe",
    fix  : "12.0.6690.5000"
  );

  check_vuln(
    name : name,
    kb   : "2596763",
    path : commonprogramfiles + "\Microsoft Shared\web server extensions\12\ISAPI\MICROSOFT.OFFICE.POLICY.DLL",
    fix  : "12.0.6690.5000"
  );
}

######################################################################
# SharePoint Foundation 2010 SP1 / SP2
#
# [KB2837588] ONETUTIL.DLL: 14.0.7123.5000
######################################################################
if (spf_2010_path)
{
  path = spf_2010_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^14\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2837588",
      path : path,
      ver  : ver,
      fix  : "14.0.7123.5000"
    );
  }
}

######################################################################
# SharePoint Server 2010 SP1 / SP2
#
# [KB2837598] - MICROSOFT.OFFICE.POLICY.DLL: 14.0.7122.5000
# [KB2863922] - MICROSOFT.OFFICE.PROJECT.SERVER.LIBRARY.DLL: 14.0.7115.5000
######################################################################
if (sps_2010_path)
{
  name = "Office SharePoint Server 2010";

  check_vuln(
    name : name,
    kb   : "2837598",
    path : commonprogramfiles + "\Microsoft Shared\web server extensions\14\ISAPI\MICROSOFT.OFFICE.POLICY.DLL",
    fix  : "14.0.7122.5000"
  );

  name = "Microsoft Project Server 2010";

  check_vuln(
    name : name,
    kb   : "2863922",
    path : sps_2010_path + "\bin\Microsoft.Office.Project.Server.Library.dll",
    fix  : "14.0.7115.5000"
  );
}

######################################################################
# SharePoint Foundation 2013
#
# [KB2863856] ONETUTIL.DLL: 15.0.4615.1000
# [KB2863863] UNKNOWN
######################################################################
if (spf_2013_path)
{
  path = spf_2013_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^15\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2863856",
      path : path,
      ver  : ver,
      fix  : "15.0.4615.1000"
    );

    # Before checking the registry, check if the Cumulative update has been installed
    if (ver_compare(ver:ver, fix:'15.0.4631.1000') == -1)
    {
      foreach item (keys(display_names))
      {
        if ('Security Update for Microsoft SharePoint Enterprise Server 2013 (KB2863863)' >< display_names[item])
        {
          kb2863863 = TRUE;
          break;
        }
      }
      if (!kb2863863)
      {
        hotfix_add_report('\n  According to the registry, KB2863863 is missing.\n', bulletin:bulletin, kb:'2863863');
        vuln++;
      }
    }
  }
}
######################################################################
# SharePoint Server 2013
#
# [KB2863829] MSSCPI.dll: 15.0.4599.1000
# [KB2760236] MICROSOFT.OFFICE.PROJECT.SERVER.LIBRARY.DLL: 15.0.4599.1000
######################################################################
if (sps_2013_path)
{
  name = "Office SharePoint Server 2013";

  check_vuln(
    name : name,
    kb   : "2863829",
    path : sps_2013_path + "Bin\MSSCPI.dll",
    fix  : "15.0.4599.1000"
  );

  name = "Microsoft Project Server 2013";
  check_vuln(
    name : name,
    kb   : "2760236",
    path : sps_2013_path + "\bin\Microsoft.Office.Project.Server.Library.dll",
    fix  : "15.0.4599.1000"
  );
}

######################################################################
# Office Web Apps 2010 SP1 / SP2
#
# [KB2880536] sword.dll: 14.0.7123.5000
######################################################################
if (owa_2010_path)
{
  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2880536",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix  : "14.0.7123.5000"
  );
}

######################################################################
# Office Web Apps 2013
######################################################################
if (owa_2013_path)
{
  check_vuln(
    name : "Office Web Apps 2013",
    kb   : "2880453",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Web.Apps.Environment.WacServer\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.Web.Apps.Environment.WacServer.dll",
    fix  : "15.0.4611.1000"
  );
}

######################################################################
# SharePoint Client SDK 2013
######################################################################
if (spc_sdk_2013)
{
  path = windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.SharePoint.Client\v4.0_15.0.0.0__71e9bce111e9429c";
  share = hotfix_path2share(path:path);
  check_file = "Microsoft.SharePoint.Client.dll";
  old_report = hotfix_get_report();
  if (hotfix_check_fversion(path:path, file:check_file, version:'15.0.4609.1000', min_version:'15.0.0.0') == HCF_OLDER)
  {
    file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
    kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
    version = get_kb_item(kb_name);

    info =
      '\n  Product           : SharePoint Server 2013 Client Components SDK' +
      '\n  File              : ' + path + '\\' + check_file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 15.0.4609.1000\n';

    hcf_report = '';
    hotfix_add_report(old_report + info, bulletin:bulletin, kb:'2863854');
    vuln = TRUE;
  }
}

######################################################################
# SharePoint Designer 2007
######################################################################

######################################################################
# SharePoint Designer 2013
######################################################################
installs = get_kb_list("SMB/Office/SharePointDesigner/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    info = "";
    version = install - "SMB/Office/SharePointDesigner/" - "/ProductPath";
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (ver[0] == 12)
    {
      if (ver[1] == 0 && ver[2] < 6652)
      {
        info =
          '\n  Product           : SharePoint Designer 2007' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6652.5000\n';
        kb = '2596810';

        hotfix_add_report(info, bulletin:bulletin, kb:kb);
        vuln = TRUE;
      }

      share = hotfix_path2share(path:path);
      old_report = hotfix_get_report();
      check_file = "Microsoft.Web.Design.Client.dll";
      if (hotfix_check_fversion(path:path, file:check_file, version:'12.0.6690.5000', min_version:'12.0.6606.1000') == HCF_OLDER)
      {
        file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
        kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
        version = get_kb_item(kb_name);

        info =
          '\n  Product           : SharePoint Designer 2007' +
          '\n  File              : ' + path + '\\' + check_file +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 12.0.6690.5000\n';

        hcf_report = '';
        hotfix_add_report(old_report + info, bulletin:bulletin, kb:'2596861');
        vuln = TRUE;
      }
    }
    else if (ver[0] == 14)
    {
      if (spd_arches['x86'] && ver[1] == 0 && ver[2] < 7007) fixed_version = '14.0.7007.1000';
      else if (spd_arches['x64'] && ver[1] == 0 && ver[2] < 7107) fixed_version = '14.0.7107.5000';
      if (fixed_version)
      {
        info =
          '\n  Product           : SharePoint Designer 2010' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : ' + fixed_version + '\n';
        kb = '2810069';
        fixed_version = '';

        hotfix_add_report(info, bulletin:bulletin, kb:kb);
        vuln = TRUE;
      }
    }
    else if (ver[0] == 15)
    {
      if (ver[1] == 0 && ver[2] < 4567)
      {
        info =
          '\n  Product           : SharePoint Designer 2013' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 15.0.4567.1000\n';
        kb = '2752096';

        hotfix_add_report(info, bulletin:bulletin, kb:kb);
        vuln = TRUE;
      }

      if (ver[1] == 0 && ver[2] < 4615)
      {
        info =
          '\n  Product           : SharePoint Designer 2013' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 15.0.4615.1000\n';
        kb = '2863836';

        hotfix_add_report(info, bulletin:bulletin, kb:kb);
        vuln = TRUE;
      }
    }
  }
}

if (vuln)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
