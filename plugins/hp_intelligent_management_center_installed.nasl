#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(54627);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/24 16:49:03 $");

  script_name(english:"HP Intelligent Management Center Application Detection");
  script_summary(english:"Checks for HP Intelligent Management Center.");

  script_set_attribute(attribute:"synopsis", value:
"A network management application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"HP Intelligent Management Center (IMC), a network management
application, is installed on the remote Windows host.");
  # http://www8.hp.com/us/en/products/network-management/product-detail.html?oid=5443902
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a67d0d5");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Connect to the appropriate share.
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

# Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can\'t connect to remote registry.');
}

path = NULL;
key = 'SYSTEM\\CurrentControlSet\\Services\\HP iMC Server\\Parameters';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'Current Directory');
  if (!isnull(item))
  {
    path = item[1];
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'HP Intelligent Management Center was not detected on the remote host.');
}

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
xml   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\conf\\component-deploy.xml', string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can\'t connect to '+share+' share.');
}

version = NULL;
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
  exit(1, 'Couldn\'t open '+path+'\\conf\\component-deploy.xml.');
}

fsize = GetFileSize(handle:fh);
if (fsize > 10240) fsize = 10240;
if (fsize)
{
  data = ReadFile(handle:fh, length:fsize, offset:0);
  if (data && 'id="iMC-PLAT"' >< data && 
      ('name="iMC Platform - Resource Manager' >< data ||
       'name="iMC Platform - Resource Management' >< data))
  {
    data = data - strstr(data, 'id="iMC-PLAT"');
    data = strstr(data, 'deployedVersion=');
    if ('deployedVersion' >< data)
    {
      version = eregmatch(pattern:'deployedVersion="([^"]+)".*', string:data);
    }
  }
}


CloseFile(handle:fh);
NetUseDel();

if (isnull(version))
  exit(1, 'Couldn\'t get the version number from '+path+'\\conf\\component-deploy.xml.');
else
  version = version[1];

extract = eregmatch(pattern:"(.*)-(.*)", string:version);
build = NULL;

if (!isnull(extract))
{
  version = extract[1];
  build = extract[2];
}

extra = NULL;
set_kb_item(name:'SMB/HP_iMC/installed', value:TRUE);
set_kb_item(name:'SMB/HP_iMC/path', value:path);
set_kb_item(name:'SMB/HP_iMC/version', value:version);
if (!isnull(build))
{
  set_kb_item(name:'SMB/HP_iMC/build', value:build);
  extra = make_array("Build", build);
}

app = "HP Intelligent Management Center Application";
register_install(
  app_name:app,
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:hp:intelligent_management_center");

report_installs(app_name:app);
