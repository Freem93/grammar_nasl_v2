#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24709);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");
  script_name(english:"Google Desktop Detection");
  script_summary(english:"Checks if Google Desktop is installed");
 script_set_attribute(attribute:"synopsis", value:"The remote host has Google Desktop installed.");
 script_set_attribute(attribute:"description", value:
"Google Desktop, a search application for Windows that allows users to
easily search for files on the computer, is installed on the remote
host.

If the 'Advanced Features' or 'Search Across Computers' options of
Google Desktop are enabled, some data may be sent to Google's server,
potentially breaching your corporate security policy.");
 script_set_attribute(attribute:"see_also", value:"http://desktop.google.com");
 script_set_attribute(attribute:"solution", value:
"Please make sure installing Google Desktop agrees with your corporate
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/26");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:google:desktop");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");

name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

key = 'SOFTWARE\\Google\\Google Desktop';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
version = NULL;


if (!isnull(key_h))
{
  # query installed path
  value = RegQueryValue(handle:key_h, item:"install_dir");
  if (!isnull(value))
  {
    path = value[1];
    set_kb_item(name:"SMB/Google/Google Desktop/installed", value:TRUE);
    set_kb_item(name:"SMB/Google/Google Dektop/path", value:path);
  }

  # query installed version
  value = RegQueryValue(handle:key_h, item:"installed_version");
  if (!isnull(value))
  {
    version = value[1];
    set_kb_item(name:"SMB/Google/Google Dektop/version", value:version);
  }

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel();

# Generate report

info = "";

if (!isnull(path))
{
  info += "Installation Path : "+path+'\n';
}
if (!isnull(version))
{
  info  += "Program Version : "+version+'\n';
}

register_install(
  app_name:"Google Desktop",
  path:path,
  version:version,
  cpe:"cpe:/a:google:desktop");

if (!isnull(path) || !isnull(version))
{
  report += 'Google Desktop is installed.\n\n';
  report = string (report,info);
  security_note(port:port, extra:report);
}
