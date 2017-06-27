#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55817);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"IBM Tivoli Endpoint Manager Client Detection");
  script_summary(english:"Checks to see if the app is installed");

  script_set_attribute(attribute:"synopsis", value:"An endpoint management client is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"IBM Tivoli Endpoint Manager Client (formerly BigFix Enterprise Suite
Client) is installed on the remote Windows host. This software is used
to facilitate management of the system.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/software/tivoli/solutions/endpoint/?s_pkg=bfwm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:ibm:tivoli_endpoint_manager_client");
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

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# even the rebranded IBM version of the software uses this key
key = "SOFTWARE\BigFix\EnterpriseClient";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;

if (!isnull(key_h))
{
  ret = RegQueryValue(handle:key_h, item:'EnterpriseClientFolder');
  if (!isnull(ret))
    path = ret[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'TEM Client doesn\'t appear to be installed.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\BESClientUI.exe', string:path);

NetUseDel(close:FALSE);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver = NULL;
exe_found = FALSE;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  exe_found = TRUE;
}

NetUseDel();

if (!exe_found)
  exit(0, 'File not found: ' + path + '\\BESClientUI.exe');
if (isnull(ver))
  exit(1, 'Error getting version from ' + path + '\\BESClientUI.exe');

version = join(ver, sep:'.');

set_kb_item(name:'SMB/ibm_tem_client/Path', value:path);
set_kb_item(name:'SMB/ibm_tem_client/Version', value:version);

register_install(
  app_name:"IBM Tivoli Endpoint Manager Client",
  path:path,
  version:version,
  cpe:"x-cpe:/a:ibm:tivoli_endpoint_manager_client");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
