#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(55550);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/22 20:52:04 $");

  script_name(english:"HP Data Protector Installed (Windows) (credentialed check)");
  script_summary(english:"Checks for HP Data Protector");

  script_set_attribute(attribute:"synopsis", value:"A backup service is running on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"HP Data Protector, or HP OpenView Storage Data Protector as it was
formerly known, a data management solution, is installed on the remote
Windows host.");

  # http://www8.hp.com/us/en/software-solutions/software.html?compURI=1175640#.UZUKy0pIFXw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bfa31296");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('misc_func.inc');
include("audit.inc");
include("install_func.inc");

function mk_unicode(str)
{
  local_var i, l, null, res;

  l = strlen(str);
  null = '\x00';
  res = "";

  for (i=0; i<l; i++)
    res += str[i] + null;

  return res;
}

name   = kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();




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

path = NULL;
datapath = NULL;
type = NULL;
build = NULL;
regver = NULL;
key = 'SOFTWARE\\Hewlett-Packard\\OpenView\\OmniBackII\\Common';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'HomeDir');
  if (!isnull(item)) path = item[1];

  item = RegQueryValue(handle:key_h, item:'DataDir');
  if (!isnull(item)) datapath = item[1];

  item = RegQueryValue(handle:key_h, item:'InstallationType');
  if (!isnull(item)) type = item[1];
  RegCloseKey(handle:key_h);
}

# Get version from uninstalled displayname, which may be more up-to-date.
regkey = hotfix_displayname_in_uninstall_key(pattern: "^HPE? Data Protector");
regkey = get_kb_item(regkey);

if(!empty_or_null(regkey))
{
  regver = eregmatch(string:regkey, pattern: "A\.\d+\.\d+");
  regver = regver[0];
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, 'HP Data Protector is not installed on the remote host.');
}
if (isnull(type)) type = 'Unknown';

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\bin\\omnicheck.exe', string:path);
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
if (isnull(fh))
{
  NetUseDel();
  exit(1, 'Couldn\'t open \''+path+'\\bin\\omnicheck.exe\'.');
}

ver = GetFileVersion(handle:fh);
verui = GetProductVersion(handle:fh);
CloseFile(handle:fh);

# If the version is later than A.06.20, check if encryption is enabled.
encrypt_comm = FALSE;
if (
  !isnull(ver) && !isnull(datapath) &&
  (
    ver[0] > 6 ||
    (ver[0] == 6 && ver[1] >= 20)
  )
)
{
  if ((type == 'Unknown') || (type == 'Client')) cnf = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Config\\Client\\config', string:datapath);
  else cnf = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Config\\Server\\config', string:datapath);
  fh = CreateFile(
    file:cnf,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize > 10240) fsize = 10240;
    if (fsize)
    {
      data = ReadFile(handle:fh, length:fsize, offset:0);
      if (
        strlen(data) &&
        ('encryption={' >< data && 'enabled=1' >< data) ||
        (mk_unicode(str:'encryption={') >< data && mk_unicode(str:'enabled=1') >< data)
      ) encrypt_comm = TRUE;
    }
    CloseFile(handle:fh);
  }
}
NetUseDel();

if (isnull(ver)) exit(1, 'Couldn\'t get the version number from \''+path+'\\omnicheck.exe\'.');

# Check if the version from registry displayname > file system ver
if(!empty_or_null(regver))
{
  regver_numeric = split(regver,sep:'.', keep:FALSE);
  regver_numeric = join(regver_numeric[1],regver_numeric[2],sep:".");
  verui_numeric = split(verui,sep:'.', keep:FALSE);
  verui_numeric = join(verui_numeric[1],verui_numeric[2],sep:".");

  # if registry ver > file sys ver, verui = regver
  if(ver_compare(ver: regver_numeric, fix: verui_numeric, strict: FALSE) > 0) verui = regver;
}

# Build can be grabbed from fileversion, == version[2]
build = version[2];

version = join(ver, sep:'.');
set_kb_item(name:'SMB/HP Data Protector/Path', value:path);
set_kb_item(name:'SMB/HP Data Protector/Version', value:version);
set_kb_item(name:'SMB/HP Data Protector/VersionUI', value:verui);
set_kb_item(name:'SMB/HP Data Protector/Type', value:type);
set_kb_item(name:'SMB/HP Data Protector/Encrypted', value:encrypt_comm);

# Setting kb to be used with hp_data_protector_version.inc
if(!empty_or_null(build) && build != 0) replace_kb_item (name:"Services/data_protector/build", value:build);
replace_kb_item (name:"Services/data_protector/version", value:verui);


register_install(
  app_name:"HP Data Protector",
  path:path,
  version:version,
  display_version:verui,
  extra:make_array("Type", type,"Encrypted", encrypt_comm),
  cpe:"cpe:/a:hp:storage_data_protector");

if (report_verbosity > 0)
{
  report =
    '\n  Path         : ' + path +
    '\n  Install type : ' + type +
    '\n  Version      : ' + verui + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
