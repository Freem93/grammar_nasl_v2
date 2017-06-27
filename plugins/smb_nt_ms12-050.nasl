#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59913);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id(
    "CVE-2012-1858",
    "CVE-2012-1859",
    "CVE-2012-1860",
    "CVE-2012-1861",
    "CVE-2012-1862",
    "CVE-2012-1863"
  );
  script_bugtraq_id(53842, 54312, 54313, 54314, 54315, 54316);
  script_osvdb_id(82861, 83647, 83648, 83649, 83650, 83651);
  script_xref(name:"EDB-ID", value:"19777");
  script_xref(name:"MSFT", value:"MS12-050");

  script_name(english:"MS12-050: Vulnerabilities in SharePoint Could Allow Elevation of Privilege (2695502)");
  script_summary(english:"Checks InfoPath / SharePoint / Groove / Office Web Apps version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple privilege escalation and
information disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The versions of InfoPath, Office SharePoint Server, SharePoint Server,
Groove Server, Windows SharePoint Services, SharePoint Foundation, or
Office Web Apps installed on the remote host are affected by multiple
privilege escalation and information disclosure vulnerabilities :

  - An information disclosure vulnerability exists in the
    way that HTML strings are sanitized. An attacker who
    successfully exploited this vulnerability could perform
    cross-site scripting attacks and run script in the
    security context of the logged-on user. (CVE-2012-1858)

  - A cross-site scripting and a privilege escalation
    vulnerability allow attacker-controlled JavaScript to
    run in the context of the user clicking a link. An
    anonymous attacker could also potentially issue
    SharePoint commands in the context of an authenticated
    user on the site. (CVE-2012-1859)

  - An information disclosure vulnerability exists in the
    way that SharePoint stores search scopes. An attacker
    could view or tamper with other users' search scopes.
    (CVE-2012-1860)

  - A cross-site scripting vulnerability exists that allows
    attacker-controlled JavaScript to run in the context of
    the user clicking a link. An anonymous attacker could
    also potentially issue SharePoint commands in the
    context of an authenticated user. (CVE-2012-1861)

  - A URL redirection vulnerability exists in SharePoint.
    The vulnerability could lead to spoofing and information
    disclosure and could allow an attacker to redirect a
    user to an external URL. (CVE-2012-1862)

  - A cross-site scripting vulnerability exists that allows
    attacker-controlled JavaScript to run in the context of
    the user clicking a link. An anonymous attacker could
    also potentially issue SharePoint commands in the
    context of an authenticated user. (CVE-2012-1863).");
  # http://blog.watchfire.com/wfblog/2012/07/tostatichtml-the-second-encounter-cve-2012-1858-html-sanitizing-information-disclosure-introduction-t.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7d49512");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-050");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for InfoPath 2007, InfoPath
2010, Office SharePoint Server 2007, SharePoint Server 2010, Groove
Server 2010, Windows SharePoint Services 2.0 and 3.0, SharePoint
Foundation 2010, and Office Web Apps 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_services");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
  path = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:"\1\");

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

bulletin = "MS12-050";
kbs = make_list(
  2596666, 2596786, 2553431, 2553322,
  2596663, 2596942, 2553424, 2553194,
  2589325, 2596911, 2553365, 2598239, 2760604
);
if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get path information for SharePoint Server 2007.
sps_2007_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\12.0\InstallPath"
);

# Get path information for SharePoint Server 2010.
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

# Get path information for SharePoint Services 2.0
sps_20_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\6.0\Location"
);

# Get path information for SharePoint Services 3.0 or SharePoint Foundation 2010.
foreach ver (make_list("12.0", "14.0"))
{
  spf_2010_path = get_registry_value(
    handle : hklm,
    item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\" + ver + "\Location"
  );

  if (spf_2010_path)
    break;
}

# Get path information for Groove Server 2010.
gs_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\Groove\Groove Relay\Parameters\InstallDir"
);

# Close connection to registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Get path and version information for InfoPath.
ip_installs = get_kb_list("SMB/Office/InfoPath/*/ProductPath");

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

if (!isnull(ip_installs))
{
  foreach install (keys(ip_installs))
  {
    ip_ver = install - 'SMB/Office/InfoPath/' - '/ProductPath';
    ip_path = ip_installs[install];
    if (ip_path) ip_path = ereg_replace(string:ip_path, pattern:"(.*)(\\[^\\]+)$", replace:"\1");

    ######################################################################
    # InfoPath 2007 SP2 / SP3
    #
    # [KB2596666] Infopath.Exe: 12.0.6661.5000
    # [KB2596786] Ipeditor.dll: 12.0.6661.5000
    ######################################################################
    office_sp2007 = get_kb_item("SMB/Office/2007/SP");
    office_sp2010 = get_kb_item("SMB/Office/2010/SP");
    if (ip_ver =~ '^12\\.' && (!isnull(office_sp2007) && (office_sp2007 == 2 || office_sp2007 == 3)))
    {
      name = "InfoPath 2007";

      check_vuln(
        name : name,
        kb   : "2596666",
        path : ip_path + "\Infopath.Exe",
        fix  : "12.0.6661.5000"
      );

      check_vuln(
        name : name,
        kb   : "2596786",
        path : ip_path + "\Ipeditor.dll",
        fix  : "12.0.6661.5000"
      );
    }
    ######################################################################
    # InfoPath 2010 SP0 / SP1
    #
    # [KB2553431] Infopath.Exe: 14.0.6120.5000
    # [KB2553322] Ipeditor.dll: 14.0.6120.5000
    ######################################################################
    else if (ip_ver =~ '^14\\.' && (!isnull(office_sp2010) && (office_sp2010 == 0 || office_sp2010 == 1)))
    {
      name = "InfoPath 2010";

      check_vuln(
        name : name,
        kb   : "2553431",
        path : ip_path + "\Infopath.Exe",
        fix  : "14.0.6120.5000"
      );

      check_vuln(
        name : name,
        kb   : "2553322",
        path : ip_path + "\Ipeditor.dll",
        fix  : "14.0.6120.5000"
      );
    }
  }
}

######################################################################
# Office SharePoint Server 2007 SP2 / SP3
#
# [KB2596663] Microsoft.SharePoint.Publishing.dll: 12.0.6660.5000
# [KB2596942] Microsoft.office.excel.webui.dll: 12.0.6661.5000
######################################################################
if (sps_2007_path)
{
  name = "Office SharePoint Server 2007";

  check_vuln(
    name : name,
    kb   : "2596663",
    path : sps_2007_path + "Bin\Microsoft.SharePoint.Publishing.dll",
    fix  : "12.0.6660.5000"
  );

  share = ereg_replace(string:windir, pattern:"^([A-Za-z]):.*", replace:"\1$");
  rc = NetUseAdd(share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  dir = ereg_replace(string:windir, pattern:"^[A-Za-z]:(.*)", replace:"\1");
  subdir = "\assembly\GAC_MSIL\Microsoft.Office.Excel.WebUI\";
  file = "\Microsoft.Office.Excel.WebUI.dll";

  # Check for the DLL in each subdirectory.
  for (
    dh = FindFirstFile(pattern:dir + subdir + "*");
    !isnull(dh);
    dh = FindNextFile(handle:dh)
  )
  {
    # Skip non-directories.
    if (dh[2] & FILE_ATTRIBUTE_DIRECTORY == 0)
      continue;

    # Skip current and parent directories.
    if (dh[1] == "." || dh[1] == "..")
      continue;

    # Skip anything that doesn't look like the 2007 branch.
    if (dh[1] !~ "^12\.")
      continue;

    # Get the version number from the file, if it exists.
    path = dir + subdir + dh[1] + file;
    fh = CreateFile(
      file               : path,
      desired_access     : GENERIC_READ,
      file_attributes    : FILE_ATTRIBUTE_NORMAL,
      share_mode         : FILE_SHARE_READ,
      create_disposition : OPEN_EXISTING
    );
    if (isnull(fh))
      continue;

    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    check_vuln(
      name : name,
      kb   : "2596942",
      path : windir + subdir + dh[1] + file,
      ver  : join(ver, sep:"."),
      fix  : "12.0.6661.5000"
    );
  }

  # Clean up.
  NetUseDel(close:FALSE);
}

######################################################################
# SharePoint Server 2010 SP0 / SP1
#
# [KB2553424] Microsoft.resourcemanagement.dll: 4.0.2450.47
# [KB2553194] Ssetupui.dll: 14.0.6120.5000
######################################################################
if (sps_2010_path)
{
  name = "Office SharePoint Server 2010";

  check_vuln(
    name : name,
    kb   : "2553424",
    path : sps_2010_path + "Service\Microsoft.resourcemanagement.dll",
    fix  : "4.0.2450.47"
  );

  check_vuln(
    name : name,
    kb   : "2553194",
    path : commonprogramfiles + "\Microsoft Shared\SERVER14\Server Setup Controller\WSS.en-us\Ssetupui.dll",
    fix  : "14.0.6120.5000"
  );
}

######################################################################
# Groove Server 2010 SP0 / SP1
#
# [KB2589325] Relay.exe: 14.0.6120.5000
######################################################################
if (gs_2010_path)
{
  check_vuln(
    name : "Groove Server 2010",
    kb   : "2589325",
    path : gs_2010_path + "\Relay.exe",
    fix  : "14.0.6120.5000"
  );
}

######################################################################
# SharePoint Services 2.0
#
# [KB2760604] Onetutil.dll: 11.0.8346.0
######################################################################
if (sps_20_path)
{
  path = sps_20_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  check_vuln(
    name : "SharePoint Services 2.0",
    kb   : "2760604",
    path : path,
    fix  : "11.0.8346.0"
  );
}

######################################################################
# SharePoint Services 3.0 SP2
#
# [KB2596911] Mssrch.dll: 12.0.6660.5000
#
#
# SharePoint Foundation 2010 SP0 / SP1
#
# [KB2553365] Mssrch.dll: 14.0.6119.5000
######################################################################
if (spf_2010_path)
{
  path = spf_2010_path + "Bin\Mssrch.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^12\.")
  {
    check_vuln(
      name : "SharePoint Services 3.0",
      kb   : "2596911",
      path : path,
      ver  : ver,
      fix  : "12.0.6660.5000"
    );
  }
  else if (ver && ver =~ "^14\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2553365",
      path : path,
      ver  : ver,
      fix  : "14.0.6119.5000"
    );
  }
}

######################################################################
# Office Web Apps 2010 SP0 / SP1
#
# [KB2598239] msoserver.dll: 14.0.6120.5000
######################################################################
if (owa_2010_path)
{
  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2598239",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\msoserver.dll",
    fix  : "14.0.6120.5000"
  );
}

hotfix_check_fversion_end();

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');
# Flag the system as vulnerable.
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
set_kb_item(name:"www/0/XSS", value:TRUE);
hotfix_security_warning();
