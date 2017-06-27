#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51462);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"Rocket Software UniVerse Detection");
  script_summary(english:"Checks for Rocket Software UniVerse");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is running a relational database.");

  script_set_attribute(attribute:"description", value:
"The remote Windows host is running UniVerse, a relational database
application.");

  script_set_attribute(attribute:"see_also", value:"http://www.rocketsoftware.com/u2/products/universe");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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

# Connect to the appropriate share.
port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Get the install path
key = "SOFTWARE\IBM\UniVerse\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"UvHome");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "Rocket Software UniVerse does not appear to be installed.");
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
dll = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\bin\universe.dll", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(1, "Couldn't open '"+path+"\bin\universe.dll'.");
}

ver = GetFileVersion(handle:fh);

CloseFile(handle:fh);
NetUseDel();

if (isnull(ver))
{
  exit(1, "Failed to find the version of '"+path+"\bin\universe.dll'.");
}

version = ver[0] + '.' + ver[1] + '.' + ver[2];
build = ver[3];

set_kb_item(name:"SMB/RocketSoftware/UniVerse/Version", value:version);
set_kb_item(name:"SMB/RocketSoftware/UniVerse/Build", value:build);
set_kb_item(name:"SMB/RocketSoftware/UniVerse/Path", value:path);

register_install(
  app_name:"Rocket Software UniVerse",
  path:path,
  version:version,
  extra:make_array("Build", build));

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version +
    '\n  Build   : ' + build + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
