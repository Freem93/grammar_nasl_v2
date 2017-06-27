#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52545);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_name(english:"Citrix Secure Gateway Installed");
  script_summary(english:"Checks the registry/file system for CSG");

  script_set_attribute(attribute:"synopsis", value:"A secure gateway application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Citrix Secure Gateway is installed on the remote host. This
application provides a secure gateway between Citrix XenApp and client
devices.");
   # http://support.citrix.com/proddocs/topic/infocenter/ic-how-to-use.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d33139b3");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:secure_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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
  exit(1, "Can't connect to the remote registry.");
}

paths = NULL;
key = "SOFTWARE\Citrix\Citrix Secure Gateway";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  path = RegQueryValue(handle:key_h, item:"ProductInstallPath");
  if (!isnull(path)) path = path[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "No evidence of CSG was found in the registry.");
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
file =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\CSGmc.dll", string:path);

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# If the file can't be opened, it's likely because it's been uninstalled
installed = FALSE;
if (fh)
{
  installed = TRUE;
  set_kb_item(name:'SMB/citrix_secure_gateway/path', value:path);
  ver = GetFileVersion(handle:fh);
  if (ver)
  {
    # all the documentation refers to versions like 'x.y.z'. this
    # file's first three numbers appear to be consistent with the
    # app version, so we'll just drop the last number
    ver = ver[0] + '.' + ver[1] + '.' + ver[2];
    set_kb_item(name:'SMB/citrix_secure_gateway/ver', value:ver);
  }
  else
    ver = UNKNOWN_VER;

  CloseFile(handle:fh);
}

NetUseDel();

if (!installed) exit(0, 'No CSG installs were detected.');

register_install(
  app_name:"Citrix Secure Gateway",
  path:path,
  version:ver,
  cpe:"cpe:/a:citrix:secure_gateway");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
