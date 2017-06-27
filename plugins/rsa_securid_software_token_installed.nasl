#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57348);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/17 14:36:40 $");

  script_name(english:"RSA SecurID Software Token Installed");
  script_summary(english:"Checks for RSA SecurID Software Token");

  script_set_attribute(attribute:"synopsis", value:"An authentication application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"RSA SecurID Software Token, a two-factor authentication application,
is installed on the remote Windows host.");

  # https://www.rsa.com/en-us/products-services/identity-access-management/securid/software-tokens/software-token-for-microsoft-windows
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1d3ee24");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

app = "RSA SecurID Software Token";

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = 'SOFTWARE\\RSA\\Software Token\\Desktop';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if(!isnull(key_h))
{
  path = RegQueryValue(handle:key_h, item:'InstallDir');
  if (path) path = path[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, app);
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\SecurID.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

# Grab the version  number if the file was opened successfully
# Also, get the Product version, since that will look more familiar
# to customers
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
  audit(AUDIT_VER_FAIL, (share-'$')+":"+exe);
}

version = GetProductVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(version))
  audit(AUDIT_VER_FAIL, (share-'$')+":"+exe);

set_kb_item(name:'SMB/RSA SecurID Software Token/Version', value:version);
set_kb_item(name:'SMB/RSA SecurID Software Token/Path', value:path);

register_install(
  app_name:app,
  path:path,
  version:version
);

report_installs(app_name:app, port:port);
