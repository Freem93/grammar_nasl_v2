#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56448);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"Microsoft Host Integration Server Installed");
  script_summary(english:"Checks if HIS is installed");

  script_set_attribute(attribute:"synopsis", value:"A gateway application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Host Integration Server (HIS) is installed on the remote
host. HIS provides connectivity between Windows networks and IBM
mainframe and mid-range computers.");
  script_set_attribute(attribute:"see_also", value:"http://connect.microsoft.com/HISERVER");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:host_integration_server");
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


port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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

path = NULL;
key = "SOFTWARE\Microsoft\Host Integration Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h);
  if (!isnull(item)) path = item[1];
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "No evidence of Microsoft HIS was found in the registry.");
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = "\snabase.exe";
file =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1" + exe, string:path);

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# If the file can't be open, it's likely because it's been uninstalled
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Microsoft HIS is not actually installed.");
}

set_kb_item(name:'SMB/microsoft_his/path', value:path);

register_install(
  app_name:"Microsoft Host Integration Server",
  path:path,
  cpe:"cpe:/a:microsoft:host_integration_server");
CloseFile(handle:fh);
NetUseDel();

if (report_verbosity > 0)
{
  report = '\n  Path : ' + path + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
