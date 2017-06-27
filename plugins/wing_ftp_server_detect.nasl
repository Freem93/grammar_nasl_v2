#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54955);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"Wing FTP Server Detection");
  script_summary(english:"Checks for presence of Wing FTP Server.");

  script_set_attribute(attribute:"synopsis", value:"An server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of Wing FTP server, which offers
file transfer functionality over FTP, FTPS, and SFTP.");
  script_set_attribute(attribute:"see_also", value:"http://www.wftpserver.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/03");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:wftpserver:wing_ftp_server");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

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

function get_version(path)
{
  local_var blob, chunk, fh, length, line, lines, matches, ofs, overlap, pattern, version;

  fh = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    exit(0, "Wing FTP is no longer installed on the remote host.");
  }

  version = NULL;
  length = GetFileSize(handle:fh);
  if (length != 0)
  {
    # Choose starting offset.
    if (length < 100000) ofs = 0;
    else ofs = int((length / 10) * 5);

    overlap = 30;
    chunk = 10240;
    while (isnull(version) && ofs <= length)
    {
      blob = ReadFile(handle:fh, length:chunk, offset:ofs);
      if (strlen(blob) == 0) break;
      blob = str_replace(string:blob, find:raw_string(0), replace:" ");

      pattern = " ([0-9]+\.[0-9]+\.[0-9]+)   ";
      pattern = "(\.dat" + pattern + "|" + pattern + "http:)";

      lines = egrep(string:blob, pattern:pattern);
      foreach line (split(lines))
      {
        matches = eregmatch(string:line, pattern:pattern);
        if (matches)
        {
          if (!isnull(matches[2])) version = matches[2];
          else version = matches[3];
          break;
        }
      }

      ofs += chunk - overlap;
    }
  }
  CloseFile(handle:fh);

  return version;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Detect Wing FTP's information from its uninstall info.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1, "Could not get uninstall information from KB.");

key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Wing FTP Server")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}
if (isnull(key)) exit(0, "Wing FTP is not installed on the remote host.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to IPC share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to IPC share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Failed to connect to the remote registry.");
}

# Get the location Wing FTP was installed at.
base = NULL;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallLocation");
  if (!isnull(item))
    base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(base))
{
  NetUseDel();
  exit(1, "Failed to read Wing FTP's installation path from the registry.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
dir = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\WFTPServer.exe";
NetUseDel(close:FALSE);

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Find the version string in the executable.
version = get_version(path:dir + file);
NetUseDel();

if (isnull(version)) exit(1, "Failed to extract the version number from " + base + file + ".");

# Report our findings.
set_kb_item(name:"SMB/Wing_FTP/Installed", value:TRUE);
set_kb_item(name:"SMB/Wing_FTP/Path", value:base);
set_kb_item(name:"SMB/Wing_FTP/Version", value:version);

register_install(
  app_name:"Wing FTP Server",
  path:base,
  version:version,
  cpe:"cpe:/a:wftpserver:wing_ftp_server");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + base +
    '\n  Version : ' + version +
    '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
