#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31728);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_name(english:"VMware Player detection (Windows)");
  script_summary(english:"Checks version of VMware Player installed");

  script_set_attribute(attribute:"synopsis", value:"An OS Virtualization application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"VMware Player, an OS virtualization software that allows running
virtual machines created with VMware Workstation/Server on a Windows
or Linux PC is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/products/player/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("install_func.inc");

# Figure out where the installer recorded information about it.

list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

installstring = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "VMware Player" >< prod)
  {
   installstring = ereg_replace(pattern:"^(SMB\/Registry\/HKLM\/SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
   break;
  }
}

if(!isnull(installstring))
  player_version = get_kb_item(string(installstring,"/","DisplayVersion"));

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
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

prod_ver  = NULL;
build_ver = NULL;
path	  = NULL;

key = "SOFTWARE\VMware, Inc.\VMware Player";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If VMware Player is installed...
  item = RegQueryValue(handle:key_h, item:"ProductVersion");
  if (!isnull(item))
  {
    prod_ver = item[1];
  }
  item = RegQueryValue(handle:key_h, item:"BuildNumber");
  if (!isnull(item))
  {
    build_ver = item[1];
  }
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}

if(isnull(path))
{
 # Try another registry location known to include VM player
 # path info.

  key = "SOFTWARE\VMware, Inc.\VMware Workstation";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallPath");
    if (!isnull(item))
     {
       path = item[1];
       if ("VMware Player" >< path)
       path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);

       RegCloseKey(handle:key_h);
     }
  }
}

RegCloseKey(handle:hklm);

if (!path)
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "VMware Player");
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\vmplayer.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

ver = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

# VMware Player file version is not the same as the one indicated
# in the registry. For e.g at the time of writing this plugin the file
# version was 6.0.3 where as the registry correctly pointed to
# the current version i.e. 2.0.3 with the build number. But we do sanity
# checks to make sure VMware player was not accidentally wiped
# off from hard drive, resulting in a false positive. If we can
# obtain ver, it is clear that the VMware player is installed and
# therefore, we rely on registry for version info.

if (isnull(ver)) audit(AUDIT_VER_FAIL, path);

if (isnull(prod_ver))
{
 prod_ver = player_version; # Version from installer entries.
 if(isnull(prod_ver)) audit(AUDIT_VER_FAIL, path);
}

if (!isnull(prod_ver))
{
 set_kb_item(name:"VMware/Player/Version", value:prod_ver);
 set_kb_item(name:"VMware/Player/Path", value:path);
}

extra = make_array();

if(!isnull(build_ver))
{
 v = split(prod_ver,sep:".",keep:FALSE);
 build = string(v[0],".",v[1],".",v[2],".",build_ver);
 set_kb_item(name:"VMware/Player/BuildVersion", value:build);
 extra['Build'] = build_ver;
}

register_install(
  app_name:"VMware Player",
  path:path,
  version:prod_ver,
  extra:extra,
  cpe:"cpe:/a:vmware:player");

if (report_verbosity > 0)
{
 if (build_ver)
 {
   report =
     '\n  Path    : ' + path +
     '\n  Version : ' + prod_ver + ' build (' + build_ver + ')' + '\n';
 }
 else
 {
   report =
     '\n  Path    : ' + path +
     '\n  Version : ' + prod_ver + '\n';
 }
 security_note(port:port, extra:report);
}
else security_note(port:port);
