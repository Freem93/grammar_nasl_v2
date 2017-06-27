#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35717);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"Dropbox Software Detection");
  script_summary(english:"Checks Windows Registry for Dropbox");

  script_set_attribute(attribute:"synopsis", value:"There is a file synchronization application on the remote host.");
  script_set_attribute(attribute:"description", value:
"Dropbox is installed on the remote host. Dropbox is an application for
storing and synchronizing files between computers, possibly outside
the organization.");
  script_set_attribute(attribute:"see_also", value:"https://www.dropbox.com/");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dropbox:dropbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139,445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");

# Walk up the path and check if each directory
# in the path is a reparse point
function reparse_points_exist_in_path(check_path)
{
  local_var check_ret;
  while (check_path != '\\' && strlen(check_path) > 0)
  {
    check_ret = FindFirstFile(pattern:check_path);

    # Look for reparse point directories
    # in file attributes
    if(!isnull(check_ret[2]) &&
      # FILE_ATTRIBUTE_DIRECTORY
      ((check_ret[2] >> 4) & 0x1) &&
      # FILE_ATTRIBUTE_REPARSE_POINT
      ((check_ret[2] >> 10) && 0x1)
    )
      return TRUE;

    check_path = ereg_replace(
      pattern:'^(.*)\\\\([^\\\\]*)?$',
      replace:"\1",
      string:check_path
    );
  }
  return FALSE;
}

kb_base = "SMB/Dropbox";


# Look for it in the Uninstall hive.
installstring = "";
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "Dropbox" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\", string:installstring);
      break;
    }
  }
}


# Connect to the appropriate share
name      = kb_smb_name();
port      = kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login     = kb_smb_login();
pass      = kb_smb_password();
domain    = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# Find where it's installed.
paths = make_array();
pdir = "";
search_needed = FALSE;

if (installstring)
{
  key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = item[1];
      lcpath = tolower(path);
      if (!paths[lcpath]) paths[lcpath] = path;
    }
    RegCloseKey(handle:key_h);
  }
}

if (max_index(keys(paths)) == 0)
{
  for (i=1; i<5; i++)
  {
    key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\DropboxExt"+i;
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      search_needed = TRUE;
      RegCloseKey(handle:key_h);
      break;
    }
  }

  # Find out where user directories are stored.
  if (search_needed | thorough_tests)
  {
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:"ProfilesDirectory");
      if (!isnull(item)) pdir = item[1];

      RegCloseKey(handle:key_h);
    }

    if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
    {
      key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        item = RegQueryValue(handle:key_h, item:"SystemRoot");
        if (!isnull(item))
        {
          winroot = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1:", string:item[1]);
          pdir = winroot + substr(pdir, strlen("%systemdrive%"));
        }

        RegCloseKey(handle:key_h);
      }
    }
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);


if (pdir)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:pdir);
  dirpat = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\*", string:pdir);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    retx = FindFirstFile(pattern:dirpat);
    while (!isnull(retx[1]))
    {
      user = retx[1];
      if (user != "." && user != "..")
      {
        path = pdir + "\" + user + "\Application Data\Dropbox\bin";
        lcpath = tolower(path);
        if (!paths[lcpath]) paths[lcpath] = path;
      }
      retx = FindNextFile(handle:retx);
    }
  }
}


extra = '';
if (!thorough_tests) extra = ' Note that Nessus will not detect Dropbox instances installed by non-admin users unless the \'Perform thorough tests\' setting is enabled.';
if (max_index(keys(paths)) == 0)
{
  NetUseDel();
  exit(0, "Dropbox does not appear to be installed." + extra);
}


# Look for installs and prepare report.
info = "";

foreach path (paths)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Dropbox.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    # Look for, and skip, Windows Reparse Points
    # that would cause one install to be reported
    # twice.
    strip_path = dirpat - "\*";
    if (reparse_points_exist_in_path(check_path:strip_path))
      continue;
    fh = CreateFile(
      file:exe,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);
      version = join(ver, sep:".");

      info += '\n  Path    : ' + path +
              '\n  Version : ' + version + '\n';

      set_kb_item(name:kb_base+"/"+version, value:path);

      register_install(
        app_name:"Dropbox Software",
        path:path,
        version:version,
        cpe:"cpe:/a:dropbox:dropbox");
    }
  }
}

if (info)
{
  set_kb_item(name:kb_base+"/Installed", value:TRUE);

  if (report_verbosity > 0) security_note(port:port, extra:info);
  else security_note(port);
  exit(0);
}
else exit(0, "No Dropbox installs were found although traces of it were found in the registry."+extra);
