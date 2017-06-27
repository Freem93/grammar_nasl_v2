#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45048);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_name(english:"Google Picasa Detection (Windows)");
  script_summary(english:"Checks for Google Picasa on Windows");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains a photo organizer.");
  script_set_attribute(attribute:"description", value:
"Google Picasa, a photo organizer from Google, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://picasa.google.com/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:picasa");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

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

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Check for Picasa 2
key = "SOFTWARE\Google\Picasa\Picasa2";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Directory");

  if (!isnull(item))
    p2path = item[1];

  RegCloseKey(handle:key_h);
}

key = "SOFTWARE\Classes\Applications\picasaphotoviewer.exe\shell\open\command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);

  if (!isnull(item))
    p3path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:item[1]);

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Get version info.
installs = make_array();
version_uis = make_array();

# - Picasa 2.x
if (p2path)
{
  # The build info isn't in the file metadata, but is in currentversion.ini
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:p2path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  dir = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:p2path);

  # Get the first two version numbers from the file metadata...
  exe = dir+"\Picasa2.exe";
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

    # ...and the last two from the .ini file
    ini = dir+"\update\LifeScapeUpdater\currentversion.ini";
    fh = CreateFile(
      file:ini,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      # The build for 2.2.28.20 was on the 2nd line of the file - the loop
      # is just to be safe
      len = GetFileSize(handle:fh);
      read = 0;

      if (len > 1024) len = 1024;
      while (read < len)
      {
        if (len - read < 1024)
          data = ReadFile(handle:fh, length:len-read, offset:read);
        else
          data = ReadFile(handle:fh, length:1024, offset:read);

        read += strlen(data);
        if (strlen(data) > 0) read += strlen(data);
        else
        {
          CloseFile(handle:fh);
          NetUseDel();
          exit(1, 'Error reading from "'+p2path+'".');
        }

        pattern = 'versionID=([0-9.]+)';
        match = eregmatch(string:data, pattern:pattern);
        if (match)
        {
          build = split(match[1], sep:'.', keep:FALSE);
          ver[2] = build[0];
          ver[3] = build[1];
          version = join(ver, sep:'.');

          installs[version] = p2path;
          version_uis[version] = strcat(ver[0], ".", ver[1], " Build ", ver[2], ".", ver[3]);
          break;
        }
      }
      CloseFile(handle:fh);
    }
  }
  NetUseDel(close:FALSE);
}

# - Picasa 3.x
if (p3path)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:p3path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  dir = ereg_replace(pattern:"^(.*)\\[^\\]+", replace:"\1", string:p3path);
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:p3path);

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
    if (!isnull(ver))
    {
      version = join(ver, sep:'.');
      installs[version] = dir;
      version_uis[version] = strcat(ver[0], ".", ver[1], " Build ", ver[2], ".", ver[3]);
    }
    CloseFile(handle:fh);
  }
  NetUseDel();
}

num_installs = max_index(keys(installs));
if (num_installs == 0) exit(0, "Google Picasa wasn't detected.");

set_kb_item(name:'SMB/Google_Picasa/Installed', value:TRUE);
if (num_installs > 1) s = "s of Google Picasa are";
else s = " of Google Picasa is";

report = '\nThe following instance'+s+' installed on the remote host :\n';

foreach version (keys(installs))
{
  path = installs[version];
  version_ui = version_uis[version];

  set_kb_item(name:"SMB/Google_Picasa/Versions", value:version);
  set_kb_item(name:"SMB/Google_Picasa/"+version+"/Path", value:path);
  set_kb_item(name:"SMB/Google_Picasa/"+version+"/Version_UI", value:version_ui);
  register_install(
    app_name:"Google Picasa",
    path:path,
    version:version,
    display_version:version_ui,
    cpe:"cpe:/a:google:picasa");

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version_ui + '\n';
}

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
