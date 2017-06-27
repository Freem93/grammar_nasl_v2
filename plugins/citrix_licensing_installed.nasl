
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58562);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_name(english:"Citrix Licensing Service Detection (credentialed check)");
  script_summary(english:"Checks for Citrix Licensing Service");

  script_set_attribute(attribute:"synopsis", value:"A licensing service is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Citrix Licensing Server, a licensing service, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.citrix.com/lang/English/lp/lp_2305120.asp");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:licensing_administration_console");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

# Connect to the appropriate share.
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
  exit(1, 'Can\'t connect to IPC$ share.');
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to the remote registry.');
}

# Find where it's installed.
path = NULL;
lmcinstalled = FALSE;

key = 'SOFTWARE\\Citrix\\LicenseServer\\Install';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:'LS_Install_Dir');
  if (!isnull(value)) path = value[1];

  # For versions older than 11.10, the License Administration Console
  # is not installed by default
  value = RegQueryValue(handle:key_h, item:'LMC_Install_Dir');
  if (!isnull(value)) lmcinstalled = TRUE;

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'Citrix License Server is not installed on the remote host.');
}
NetUseDel(close:FALSE);

# Grab the file version of lmver.exe
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\lmver.exe", string:path);

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

if (isnull(fh))
{
  NetUseDel();
  exit(0, 'Couldn\'t open \''+(share-'$')+':'+exe+'\'.');
}

ver = GetProductVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version of \''+(share-'$')+':'+exe+'\'.');

version = NULL;
build = NULL;
matches = eregmatch(pattern:'^([0-9\\.]+) build ([0-9]+)$', string:ver);
if (!isnull(matches))
{
  version = matches[1];
  build = matches[2];
}
if (isnull(version))
  exit(1, 'Couldn\'t parse the version number from \''+(share-'$')+':'+exe+'\'.');

set_kb_item(name:'SMB/Citrix License Server/Path', value:path);
set_kb_item(name:'SMB/Citrix License Server/Version', value:version);
set_kb_item(name:'SMB/Citrix License Server/LMC', value:lmcinstalled);

extra = make_array("LMC", lmcinstalled);

if (!isnull(build))
{
  set_kb_item(name:'SMB/Citrix License Server/Build', value:build);
  extra["Build"] = build;
}


register_install(
  app_name:"Citrix Licensing Service",
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:citrix:licensing_administration_console");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version;
  if (!isnull(build)) report += ' build ' + build;
  report += '\n';
  security_note(port:port, extra:report);
  exit(0);
}
else security_note(port);
