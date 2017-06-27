#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55748);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"HP Insight Control Performance Management Installed");
  script_summary(english:"Checks for HP Insight Control Performance Management");

  script_set_attribute(attribute:"synopsis", value:
"A performance management product is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"HP Insight Control Performance Management is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://h18000.www1.hp.com/products/servers/management/ice/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_control_performance_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/Registry/Enumerated');

list = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (isnull(list)) exit(1, 'Could not get the Uninstall KB.');

item = NULL;
installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && 'HP Insight Control performance management' >< prod)
  {
    item = ereg_replace(pattern:'^SMB\\/Registry\\/HKLM\\/(SOFTWARE\\/Microsoft\\/Windows\\/CurrentVersion\\/Uninstall\\/.+)\\/DisplayName$', replace:'\\1', string:name);
    installstring = str_replace(find:'/', replace:'\\', string:item);
    break;
  }
}

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();





if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to IPC$ share.');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to the remote registry.');
}

# Find where it's installed
path = NULL;
if (installstring)
{
  key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:'InstallLocation');
    path = item[1];
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'HP Insight Control Performance Management was not detected on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
xml = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\pmptools.xml', string:path);
NetUseDel(close:FALSE);


rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
}

fh = CreateFile(
  file:xml,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (isnull(fh))
{
  NetUseDel();
  exit(0, 'Failed to open \''+(share-'$')+':'+xml+'\'.');
}

version = NULL;
fsize = GetFileSize(handle:fh);
if (fsize > 10240) fsize = 10240;
if (fsize)
{
  data = ReadFile(handle:fh, length:fsize, offset:0);
  if (data && '<attribute name="product-name">HP Insight Control performance management')
  {
    chunk = strstr(data, '<attribute name="product-name">HP Insight Control performance management') - strstr(data, '</web-launch-tool>');
    if (chunk)
    {
      chunk = chomp(chunk);
      version = strstr(chunk, '<attribute name="product-version"');
      version = version - strstr('</attribute');
      version = ereg_replace(pattern:'<attribute name="product-version">([0-9\\.]+).*', string:version, replace:'\\1');
    }
  }
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(version))
{
  exit(1, 'Couldn\'t get the version from '+(share-'$')+':'+xml+'\'.');
}

set_kb_item(name:'SMB/HP Insight Control Performance Management/Path', value:path);
set_kb_item(name:'SMB/HP Insight Control Performance Management/Version', value:version);

register_install(
  app_name:"HP Insight Control Performance Management",
  path:path,
  version:version,
  cpe:"cpe:/a:hp:insight_control_performance_management");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
