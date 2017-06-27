#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(31788);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_name(english:"Safari Detection (Windows)");
  script_summary(english:"Checks for Safari on Windows");

 script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains an alternative web browser.");
 script_set_attribute(attribute:"description", value:"Apple's Safari web browser is installed on the remote Windows host.");
 script_set_attribute(attribute:"see_also", value:"http://www.apple.com/safari/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/07");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Detect which registry key Safari's install used.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^Safari$")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}


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
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0, "can't connect to the remote registry");
}


# Determine where it's installed.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
# - Look in alternate locations if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Classes\SafariURL\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
      path = ereg_replace(pattern:'^"(.+)\\\\Safari\\.exe".*$', replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  key = "SOFTWARE\Clients\StartMenuInternet\Safari.exe\shell\open\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
      path = ereg_replace(pattern:'^"(.+)\\\\Safari\\.exe".*$', replace:"\1", string:item[1]);

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine its version from the executable itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Safari.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

file_ver = NULL;
prod_ver = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  if (ver) file_ver = version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];
  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
        (get_word(blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word(blob:varfileinfo['Translation'], pos:2);
      translation = tolower(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) prod_ver = data['ProductVersion'];
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Report it if we have a version number.
if (!isnull(file_ver))
{
  set_kb_item(name:"SMB/Safari/FileVersion", value:file_ver);
  if (!isnull(prod_ver)) set_kb_item(name:"SMB/Safari/ProductVersion", value:prod_ver);
  set_kb_item(name:"SMB/Safari/Path", value:path);

  register_install(
    app_name:"Safari",
    path:path,
    version:file_ver,
    cpe:"cpe:/a:apple:safari");

  if (report_verbosity)
  {
    if (isnull(prod_ver)) ver = file_ver;
    else ver = prod_ver;

    report = string(
      "\n",
      "  Version : ", ver, "\n",
      "  Path    : ", path, "\n"
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
