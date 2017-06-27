#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58398);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"HP Data Protector Express Installed");
  script_summary(english:"Checks version of dpwinsdr.exe");

  script_set_attribute(attribute:"synopsis", value:"A backup application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"HP Data Protector Express, a backup application, is installed on the
remote Windows host.");

  script_set_attribute(attribute:"see_also", value:"http://h18006.www1.hp.com/products/storage/software/datapexp/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector_express");
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

get_kb_item_or_exit('SMB/Registry/Enumerated');

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

key = 'SOFTWARE\\HP\\Data Protector Express';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:'RootPath');
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

# version 3.5 SP2 path is stored under a subkey
# SOFTWARE\HP\Data Protector Express\v3.50-sp2
if(isnull(path))
{
  key = 'SOFTWARE\\HP\\Data Protector Express';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey))
      {
        key2 = key + '\\' + subkey ;
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h, item:'RootPath');
          if (!isnull(value)) path = value[1];

          RegCloseKey(handle:key2_h);
        }
      }
    }
    RegCloseKey (handle:key_h);
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "HP Data Protector Express is not installed on the remote host.");
}
NetUseDel(close:FALSE);


# Grab the file version of file dpwinsdr.exe
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
exe =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\dpwinsdr.exe", string:path);

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

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version of \''+(share-'$')+':'+exe+'\'.');
# Versions earlier than 5.x use the format x.x.build.0 while
# version later 5.x or later use the format x.x.x.build
if (ver[0] < 5)
{
  version = ver[0] + '.' + ver[1];
  build = ver[2];
}
else
{
  version = ver[0] + '.' + ver[1] + '.' + ver[2];
  build = ver[3];
}

set_kb_item(name:'SMB/HP Data Protector Express/Path', value:path);
set_kb_item(name:'SMB/HP Data Protector Express/Version', value:version);

extra = make_array();
if (!isnull(build))
{
  set_kb_item(name:'SMB/HP Data Protector Express/Build', value:build);
  extra['Build'] = build;
}

register_install(
  app_name:"HP Data Protector Express",
  path:path,
  version:version,
  extra:extra,
  cpe:"cpe:/a:hp:data_protector_express");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + ' Build ' + build +
    '\n';
  security_note(port:port, extra:report);
  exit(0);
}
else security_note(port);
