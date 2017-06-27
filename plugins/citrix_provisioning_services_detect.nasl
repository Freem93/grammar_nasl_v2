#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51663);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/24 17:01:59 $");

  script_name(english:"Citrix Provisioning Services Detection");
  script_summary(english:"Checks for Citrix Provisioning Services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a virtualization application.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Citrix Provisioning Services, a
virtualization application.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:provisioning_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
name    = kb_smb_name();
port    = kb_smb_transport();

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Get some info about the install
path = NULL;

key = "SOFTWARE\Citrix\ProvisioningServer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"TargetDir");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path)) exit(0, "Citrix Provisioning Services doesn't appear to be installed on the remote host.");

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\StreamProcess.exe", string:path);
NetUseDel(close:FALSE);

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
  exit(1, "Failed to open '"+path+"\StreamProcess.exe'.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, "Failed to get version number of '"+path+"\StreamProcess.exe'.");

version = ver[0] + '.' + ver[1] + '.' + ver[2];
fileversion = join(sep:'.', ver);
set_kb_item(name:"SMB/Citrix/Provisioning_Services/Version", value:version);
set_kb_item(name:"SMB/Citrix/Provisioning_Services/Path", value:path);
set_kb_item(name:"SMB/Citrix/Provisioning_Services/StreamProcess.exe", value:fileversion);

register_install(
  app_name:"Citrix Provisioning Services",
  path:path,
  version:version,
  extra:make_array("exe", fileversion),
  cpe:"cpe:/a:citrix:provisioning_services");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
