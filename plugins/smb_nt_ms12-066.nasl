#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62461);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-2520");
  script_bugtraq_id(55797);
  script_osvdb_id(86059);
  script_xref(name:"MSFT", value:"MS12-066");

  script_name(english:"MS12-066: Vulnerability in HTML Sanitization Component Could Allow Elevation of Privilege (2741517)");
  script_summary(english:"Checks installed versions of various Microsoft applications.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft InfoPath, Communicator, Lync, SharePoint
Server, Groove Server, and/or Office Web Apps installed on the remote
host is potentially affected by a privilege escalation vulnerability
due to the way HTML strings are sanitized.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-066");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for InfoPath 2007, InfoPath
2010, Communicator 2007 R2, Lync 2010, Lync 2010 Attendee, SharePoint
Server 2007, SharePoint Server 2010, Groove Server 2010, SharePoint
Services 3.0, SharePoint Foundation 2010, and Office Web Apps 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
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

function get_user_dirs()
{
  local_var appdir, dirpat, domain, hklm, iter, lcpath, login, pass;
  local_var path, paths, pdir, port, rc, root, share, user, ver;

  paths = make_list();

  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  pdir = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProfilesDirectory");
  if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
  {
    root = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRoot");
    if (!isnull(root))
    {
      share = hotfix_path2share(path:root);
      pdir = share - '$' + ':' + substr(pdir, strlen("%systemdrive%"));
    }
  }
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (!pdir)
    return NULL;

  ver = get_kb_item_or_exit("SMB/WindowsVersion");

  share = hotfix_path2share(path:pdir);
  dirpat = ereg_replace(string:pdir, pattern:"^[A-Za-z]:(.*)", replace:"\1\*");

  port    =  kb_smb_transport();
  if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel(close:FALSE);
    return NULL;
  }

  # 2000 / XP / 2003
  if (ver < 6)
    appdir += "\Local Settings\Application Data";
  # Vista / 7 / 2008
  else
    appdir += "\AppData\Local";

  paths = make_array();
  iter = FindFirstFile(pattern:dirpat);
  while (!isnull(iter[1]))
  {
    user = iter[1];
    iter = FindNextFile(handle:iter);

    if (user == "." || user == "..")
      continue;

    path = pdir + '\\' + user + appdir;

    lcpath = tolower(path);
    if (isnull(paths[lcpath]))
      paths[lcpath] = path;
  }

  NetUseDel(close:FALSE);

  return paths;
}

function get_ver()
{
  local_var fh, path, rc, share, ver;

  path = _FCT_ANON_ARGS[0];

  share = hotfix_path2share(path:path);

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

function check_vuln(fix, kb, name, path, ver, min_ver)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  # If min_ver is supplied, make sure the version is higher than the min_ver
  if (min_ver && ver_compare(ver:ver, fix:min_ver, strict:FALSE) == -1)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");
bulletin = 'MS12-066';
kbs = make_list(
  '2589280', '2687401', '2687402', '2687356',
  '2687405', '2687434', '2687435', '2687417',
  '2687436', '2687439', '2687440', '2726391',
  '2726382', '2726384', '2726388');

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry
userpaths = get_user_dirs();
arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
if (arch == "x64")
  extra = "\Wow6432Node";
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the path information for SharePoint Server 2007
sps_2007_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\12.0\InstallPath"
);

# Get the path information for SharePoint Server 2010
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

commonprogramfiles = hotfix_get_commonfilesdir();
if (!commonprogramfiles)
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
}

# Get the path information for SharePoint Services orSharePoint Foundation 2010
foreach ver (make_list("12.0", "14.0"))
{
  spf_2010_path = get_registry_value(
    handle : hklm,
    item   : 'SOFTWARE\\Microsoft\\Shared Tools\\Web Server Extensions\\' + ver + "\Location"
  );

  if (spf_2010_path)
    break;
}

# Get the path information for Groove Server 2010
gs_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\Groove\Groove Relay\Parameters\InstallDir"
);


# Get the path information for Office Web Apps
owa_2010_path = sps_2010_path;

# Get the path information for Microsoft Communicator 2007 R2
mscomm_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE\\Microsoft\\Communicator\\InstallationDirectory'
);

# Get the path information for Microsoft Lync 2010
lync_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE'+extra+'\\Microsoft\\Communicator\\InstallationDirectory'
);

# Get the path information for Microsoft Lync 2010 Attendant Admin-level install
lync_att_admin_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE\\Microsoft\\AttendeeCommunicator\\InstallationDirectory'
);

# Close connection to registry
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Get the path and version information for InfoPath
ip_installs = get_kb_list("SMB/Office/InfoPath/*/ProductPath");
if (!isnull(ip_installs))
{
  foreach install (keys(ip_installs))
  {
    ip_ver = install - 'SMB/Office/InfoPath/' - '/ProductPath';
    ip_path = ip_installs[install];

    if (ip_path)
      ip_path = ereg_replace(string:ip_path, pattern:"^(.*)(\\[^\\]+)$", replace:"\1");

    ##############################################################
    # InfoPath 2007 SP2 / SP3
    #
    # [KB2687439] INFOPATH.EXE - 12.0.6662.5004
    # [KB2687440] IPEDITOR.DLL - 12.0.6662.5004
    ##############################################################
    if (ip_ver =~ '^12\\.')
    {
      name = "InfoPath 2007";

      check_vuln(
        name : name,
        kb   : "2687439",
        path : ip_path + "\Infopath.exe",
        fix  : "12.0.6662.5004"
      );

      check_vuln(
        name : name,
        kb   : "2687440",
        path : ip_path + "\Ipeditor.dll",
        fix  : "12.0.6662.5004"
      );
    }

    ##############################################################
    # InfoPath 2010 SP1
    #
    # [KB2687417] IPEDITOR.DLL - 14.0.6126.5000
    # [KB2687436] INFOPATH.EXE - 14.0.6123.5006
    ##############################################################
    if (ip_ver =~ '14\\.')
    {
      name = "InfoPath 2010";

      check_vuln(
        name : name,
        kb   : "2687439",
        path : ip_path + "\Infopath.exe",
        fix  : "14.0.6123.5006"
      );

      check_vuln(
        name : name,
        kb   : "2687417",
        path : ip_path + "\Ipeditor.dll",
       fix  : "14.0.6126.5000"
      );
    }
  }
}

#############################################################
# Microsoft Communicator 2007 R2
#
# [KB2726391] COMMUNICATOR.EXE - 3.5.6907.261
#############################################################
if (mscomm_path)
{
  name = "Microsoft Communicator 2007 R2";
  check_vuln(
    name    : name,
    kb      : "2726391",
    path    : mscomm_path + "\Communicator.exe",
    min_ver : "3.5.0.0",
    fix     : "3.5.6907.261"
  );
}

#############################################################
# Microsoft Lync 2010
#
# [KB2726382] COMMUNICATOR.EXE - 4.0.7577.4109
#############################################################
if (lync_path)
{
  name = "Microsoft Lync 2010";
  check_vuln(
    name    : name,
    kb      : "2726382",
    path    : lync_path + "\Communicator.exe",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4109"
  );
}

#############################################################
# Microsoft Lync 2010 Attendee (admin level install)
#
# [KB2726388] - MeetingJoinAxAOC.DLL - 4.0.7577.4109
#############################################################
if (lync_att_admin_path)
{
  name = "Microsoft Lync 2010 Attendee (admin-level install)";
  check_vuln(
    name    : name,
    kb      : "2726388",
    path    : lync_att_admin_path + "\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4109"
  );
}

#############################################################
# Microsoft Lync 2010 Attendee (user level install)
#
# [KB2726384] - MeetingJoinAxAOC.DLL
#############################################################
if (max_index(keys(userpaths)) > 0)
{
  foreach userdir (keys(userpaths))
  {
    name = "Microsoft Lync 2010 Attendee (user-level install)";
    check_vuln(
      name    : name,
      kb      : "2726384",
      path    : userdir + "\Microsoft Lync Attendee\MeetingJoinAxAOC.DLL",
      min_ver : "4.0.0.0",
      fix     : "4.0.7577.4109"
    );
  }
}

#############################################################
# Microsoft SharePoint Server 2007 SP2 / SP3
#
# [KB2687405] - Microsoft.SharePoint.Publishing.dll: 12.0.6664.5000
#############################################################
if (sps_2007_path)
{
  name = "Office SharePoint Server 2007";

  check_vuln(
    name : name,
    kb   : "2687405",
    path : sps_2007_path + "Bin\Microsoft.SharePoint.Publishing.dll",
    fix  : "12.0.6664.5000"
  );
}

#############################################################
# SharePoint Server 2010 SP1
#
# [KB2687435] - OSAFEHTM.DLL - 14.0.6123.5006
# [KB2589280] - Microsoft.Office.Policy.dll - 14.0.6123.5000
#############################################################
if (sps_2010_path)
{
  name = "Office SharePoint Server 2010";

  check_vuln(
    name : name,
    kb   : "2687435",
    path : commonprogramfiles + "\Microsoft Shared\Web Server Extensions\14\BIN\Osafehtm.dll",
    fix  : "14.0.6123.5006"
  );

  check_vuln(
    name : name,
    kb   : "2589280",
    path : commonprogramfiles + "\Microsoft Shared\Web Server Extensions\14\ISAPI\Microsoft.Office.Policy.dll",
    fix  : "14.0.6123.5000"
  );
}

#############################################################
# Groove Server 2010 SP1
#
# [KB2687402] - Relay.exe - 14.0.6123.5006
#############################################################
if (gs_2010_path)
{
  check_vuln(
    name : "Groove Server 2010",
    kb   : "2687402",
    path : gs_2010_path + "\Relay.exe",
    fix  : "14.0.6123.5006"
  );
}


#############################################################
# SharePoint Services 3.0 SP2
#
# [KB2687356] - STSOM.DLL - 12.0.6665.5000
#
# SharePoint Foundation 2010 SP1
# [KB2553365] - STSOM.DLL - 14.0.6123.5006
#############################################################
if (spf_2010_path)
{
  path = spf_2010_path + "Bin\stswel.dll";
  ver = get_ver(path);

  if (ver && ver =~ '^12\\.')
  {
    check_vuln(
      name : "SharePoint Services 3.0",
      kb   : "2687356",
      path : path,
      ver  : ver,
      fix  : "12.0.6665.5000"
    );
  }
  else if (ver && ver =~ '^14\\.')
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2553365",
      path : path,
      ver  : ver,
      fix  : "14.0.6123.5006"
    );
  }
}

#############################################################
# Office Web Apps 2010 SP1
#
# [KB2687401] - sword.dll - 14.0.6123.5005
#############################################################
if (owa_2010_path)
{
  check_vuln(
    name : "Office Web Apps",
    kb   : "2687401",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix : "14.0.6123.5005"
  );
}

hotfix_check_fversion_end();

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
set_kb_item(name:"www/0/XSS", value:TRUE);
hotfix_security_warning();
