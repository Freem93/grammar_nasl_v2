#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58292);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"iCloud Detection (Windows)");
  script_summary(english:"Checks for iCloud in registry / on filesystem");

  script_set_attribute(attribute:"synopsis", value:
"A cloud storage / computing application is installed on the remote
host.");
  script_set_attribute(attribute:"description", value:
"iCloud is installed on this host. It is a cloud storage and computing
service from Apple.");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/icloud/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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


kb_base = "SMB/iCloud";


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


# Connect to remote registry.
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


# Find where it's installed.
path = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "iCloud" >< prod)
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);

      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        item = RegQueryValue(handle:key_h, item:"InstallLocation");
        if (!isnull(item)) path = item[1];

        RegCloseKey(handle:key_h);
      }
    }
  }
}

if (isnull(path))
{
  clsid = NULL;

  foreach class (make_list("iCloudServices.AccountInfo", "iCloudServices.NCAccount"))
  {
    key = "SOFTWARE\Classes\" + class + "\CLSID";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(item)) clsid = item[1];

      RegCloseKey(handle:key_h);
    }
    if (clsid) break;
  }

  if (clsid)
  {
    key = "SOFTWARE\Classes\CLSID\"+clsid+"\LocalServer32";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(item))
      {
        path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\..+$', replace:"\1", string:item[1]);
      }

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0, "No evidence of iCloud was found in the registry.");
}
NetUseDel(close:FALSE);


# Determine the version of the file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\iCloud.exe", string:path);
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
  exit(0, "iCloud is not installed, although traces of it exist in the registry.");
}

set_kb_item(name:kb_base+"/Installed", value:TRUE);
set_kb_item(name:kb_base+"/Path", value:path);

report = '\n  Path    : ' + path;

file_ver = GetFileVersion(handle:fh);
product_version = GetProductVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (!isnull(file_ver))
{
  file_version = join(sep:".", file_ver);
  set_kb_item(name:kb_base+"/FileVersion", value:file_version);
}
if (!isnull(product_version))
{
  product_version = str_replace(find:", ", replace:".", string:product_version);
  # Remove fourth set of digits if it's 0 and the last set.
  if (ereg(pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.0$", string:product_version))
    product_version = substr(product_version, 0, strlen(product_version)-3);
  set_kb_item(name:kb_base+"/ProductVersion", value:product_version);
  report += '\n  Version : ' + product_version;
}

register_install(
  app_name:"iCloud",
  path:path,
  version:product_version);

if (report_verbosity > 0)
{
  report += '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
