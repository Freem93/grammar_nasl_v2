#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58401);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"Novell GroupWise Client Installed");
  script_summary(english:"Checks for Novell GroupWise client");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has an email client application installed.");
  script_set_attribute(attribute:"description", value:
"Novell GroupWise, an email client, is installed on the remote Windows
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/products/groupwise/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include("audit.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

name    = kb_smb_name();
port    = kb_smb_transport();
#if (!get_port_state(port)) exit(0, 'Port '+port+' is not open.');
login   = kb_smb_login();
pass    = kb_smb_password();
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
  exit(1, 'Can\'t connect to the remote registry.');
}

# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Clients\Mail\GroupWise\Shell\Open\Command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
  {
    path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:value[1]);
    path = ereg_replace(pattern:'^(.*)\\\\.*', replace:"\1", string:path);
  }

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, 'Novell GroupWise Client does not appear to be installed.');
}
NetUseDel(close:FALSE);


# Grab the file version of the client.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\grpwise.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(0, 'Failed to open \''+(share-'$')+':'+exe+'\'.');
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version of \''+(share-'$')+':'+exe+'\'.');
version = join(ver, sep:'.');

set_kb_item(name:'SMB/Novell GroupWise Client/Path', value:path);
set_kb_item(name:'SMB/Novell GroupWise Client/Version', value:version);

register_install(
  app_name:"Novell GroupWise Client",
  path:path,
  version:version,
  cpe:"cpe:/a:novell:groupwise");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
