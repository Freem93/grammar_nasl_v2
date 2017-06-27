#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11425);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

 script_name(english:"ICQ Detection");
 script_summary(english:"Determines if ICQ is installed");

 script_set_attribute(attribute:"synopsis", value:
"There is an instant messaging client installed on the remote Windows
host.");
 script_set_attribute(attribute:"description", value:
"ICQ is installed on the remote host. ICQ is an instant messaging
client for Windows that also includes some peer-to-peer file sharing
features. As such, it may not be suitable for use in a business
environment.");
 script_set_attribute(attribute:"see_also", value:"http://www.icq.com/");
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not agree with your
organization's security and/or acceptable use policies.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/21");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();



 script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1);


# Detect which registry key the toolbar install used.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
toolbar_key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod == "ICQ Toolbar")
  {
    toolbar_key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    toolbar_key = str_replace(find:"/", replace:"\", string:toolbar_key);
    break;
  }
}


name	= kb_smb_name();
login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();




if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
 NetUseDel();
 exit(1);
}


prod = NULL;
exe = NULL;
path = NULL;
toolbar_dll = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ICQ.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  prod = "ICQ";

  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) exe = value[1];

  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
if (isnull(exe))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ICQLite.exe";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    prod = "ICQLite";

    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) exe = value[1];

    value = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(value))
    {
      path = value[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
if (!isnull(toolbar_key))
{
  key_h = RegOpenKey(handle:hklm, key:toolbar_key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"UninstallString");
    if (!isnull(item))
    {
      s = item[1];
      toolbar_dll = ereg_replace(pattern:'^regsvr.+"(.+)".*$', replace:"\1", string:s);
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


if (prod && exe && path)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # Distinguish between 6 builds 6043 and 6059.
  if (
    !isnull(ver) &&
    !isnull(toolbar_dll) &&
    (ver[0] == 6 && ver[1] == 0 && ver[2] == 0 && ver[3] == 6043)
  )
  {
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:toolbar_dll);
    dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:toolbar_dll);

    NetUseDel(close:FALSE);
    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(0);
    }

    fh = CreateFile(
      file:dll,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );

    if (!isnull(fh))
    {
      toolbar_ver = GetFileVersion(handle:fh);
      if (
        !isnull(toolbar_ver) &&
        (toolbar_ver[0] == 2 && toolbar_ver[1] == 0 && toolbar_ver[2] == 22 && toolbar_ver[3] == 36)
      ) ver[3] = 6059;
      CloseFile(handle:fh);
    }
    NetUseDel(close:FALSE);
  }

  # If the version number's available, save and report it.
  if (!isnull(ver))
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    set_kb_item(name:"SMB/ICQ/Product", value:prod);
    set_kb_item(name:"SMB/ICQ/Version", value:version);
    set_kb_item(name:"SMB/ICQ/Path",    value:path);

    register_install(
      app_name:"ICQ",
      path:path,
      version:version,
      extra:make_array("Product", prod));

    report = string(
      "\n",
      "  Product : ", prod, "\n",
      "  Version : ", version, "\n",
      "  Path :    ", path, "\n"
    );
    security_note(port:port, extra:report);
  }
}
NetUseDel();
