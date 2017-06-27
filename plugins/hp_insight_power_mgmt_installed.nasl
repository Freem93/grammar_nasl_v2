#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47779);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"HP Insight Control Power Management Detection");
  script_summary(english:"Checks if power management is installed");

  script_set_attribute(attribute:"synopsis", value:"A power management product is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:"HP Insight Control power management is installed on the remote host.  ");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0ecc3a46");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_control");
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

name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
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
  exit(1, "Cannot connect to remote registry.");
}

# todo: test older versions
path = NULL;
key = 'SOFTWARE\\Hewlett-Packard\\IPM\\Uninstall';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  path = RegQueryValue(handle:key_h, item:'UninstallString');
  if (path)
  {
    uninst = path[1];
    path = ereg_replace(pattern:"(.*\\)[^\\]+$", replace:"\1", string:path[1]);
  }
  RegCloseKey(handle:key_h);
}

if (isnull(path))
{
  NetUseDel();
  exit(0, "HP Insight Control Power Management does not appear to be installed.");
}

ver = NULL;
key = 'SOFTWARE\\Hewlett-Packard\\IPM\\Settings';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  ver = RegQueryValue(handle:key_h, item:'Version');
  if (ver) ver = ver[1];
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(ver))
  ver = 'unknown';

# Try to access a file from the install dir to make sure the app is
# actually there
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:uninst);
file = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:uninst);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (!fh)
{
  NetUseDel();
  exit(1, "No evidence of HP IPM found in '" + path + "'.");
}
else
{
  CloseFile(handle:fh);
  NetUseDel();
}


set_kb_item(name:'SMB/hp_ipm/path', value:path);
set_kb_item(name:'SMB/hp_ipm/ver', value:ver);

register_install(
  app_name:"HP Insight Control Power Management",
  path:path,
  version:ver,
  cpe:"cpe:/a:hp:insight_control");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
