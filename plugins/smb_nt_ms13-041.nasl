#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66416);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2013-1302");
  script_bugtraq_id(59791);
  script_osvdb_id(93303);
  script_xref(name:"MSFT", value:"MS13-041");
  script_xref(name:"IAVB", value:"2013-B-0051");

  script_name(english:"MS13-041: Vulnerability in Lync Could Allow Remote Code Execution (2834695)");
  script_summary(english:"Checks installed versions of Communicator and/or Lync.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Communicator and/or Lync installed on the
remote host is potentially affected by a remote code execution if an
attacker shares specially crafted content, such as a file or program,
as a presentation in Lync or Communicator.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-041");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Communicator 2007 R2, Lync
2010, Lync 2010 Attendee, and Lync Server 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_communicator");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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


# #########################
#
# Get list of all user Directories
#
# #########################
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


# #########################
#
# Get file version
#
# #########################
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


# #########################
#
# Check if a file path/version is vulnerable
#
# #########################
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

  vuln = TRUE;}


# #########################
#
# Main
#
# #########################
get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS13-041';
kbs = make_list(
  '2827750', '2827751',
  '2827752', '2827753',
  '2827754'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry
userpaths = get_user_dirs();
arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
if (arch == "x64")
  extra = "\Wow6432Node";
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);


# Get the path information for Microsoft Communicator 2007 R2
mscomm2007r2_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE\\Microsoft\\Communicator\\InstallationDirectory'
);

# Get the path information for Microsoft Lync 2010
lync2010_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE'+extra+'\\Microsoft\\Communicator\\InstallationDirectory'
);

# Get the path information for Microsoft Lync 2010 Attendee (admin level install)
lync2010_att_admin_path = get_registry_value(
  handle : hklm,
  item   : 'SOFTWARE\\Microsoft\\AttendeeCommunicator\\InstallationDirectory'
);

# Get the path information for Microsoft Lync Server 2013 (Web Components Server)
lync2013_web_path = get_registry_value(
  handle : hklm,
  item   : 'Software\\Microsoft\\Real-Time Communications\\{2A65AB9C-57AD-4EC6-BD4E-BD61A7C583B3}\\InstallDir'
);


# Close connection to registry
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

#############################################################
# Microsoft Communicator 2007 R2
#
# [KB2827753] COMMUNICATOR.EXE - 3.5.6907.268
#############################################################
if (mscomm2007r2_path)
{
  name = "Microsoft Communicator 2007 R2";
  check_vuln(
    name    : name,
    kb      : "2827753",
    path    : mscomm2007r2_path + "\Communicator.exe",
    min_ver : "3.5.0.0",
    fix     : "3.5.6907.268"
  );
}

#############################################################
# Microsoft Lync 2010
#
# [KB2827750] communicator.exe - 4.0.7577.4388
#############################################################
if (lync2010_path)
{
  name = "Microsoft Lync 2010";
  check_vuln(
    name    : name,
    kb      : "2827750",
    path    : lync2010_path + "\communicator.exe",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4388"
  );
}

#############################################################
# Microsoft Lync 2010 Attendee (admin level install)
#
# [KB2827752] - MeetingJoinAxAOC.DLL - 4.0.7577.4388
#############################################################
if (lync2010_att_admin_path)
{
  name = "Microsoft Lync 2010 Attendee (admin-level install)";
  check_vuln(
    name    : name,
    kb      : "2827752",
    path    : lync2010_att_admin_path + "\MeetingJoinAxAOC.DLL",
    min_ver : "4.0.0.0",
    fix     : "4.0.7577.4388"
  );
}

#############################################################
# Microsoft Lync 2010 Attendee (user level install)
#
# [KB2827751] - MeetingJoinAxAOC.DLL - 4.0.7577.4388
#############################################################
if (max_index(keys(userpaths)) > 0)
{
  foreach userdir (keys(userpaths))
  {
    name = "Microsoft Lync 2010 Attendee (user-level install)";
    check_vuln(
      name    : name,
      kb      : "2827751",
      path    : userdir + "\Microsoft Lync Attendee\MeetingJoinAxAOC.DLL",
      min_ver : "4.0.0.0",
      fix     : "4.0.7577.4388"
    );
  }
}

#############################################################
# Microsoft Lync Server 2013
#
# [KB2827754] system.net.http.formatting.dll - 4.0.21112.0
#############################################################
if (lync2013_web_path)
{
  name = "Microsoft Lync Server 2013";
  check_vuln(
    name    : name,
    kb      : "2827754",
    path    : lync2013_web_path + "\Web Components\Autodiscover\Ext\Bin\system.net.http.formatting.dll",
    min_ver : "4.0.0.0",
    fix     : "4.0.21112.0"
  );
}

hotfix_check_fversion_end();

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
hotfix_security_hole();
