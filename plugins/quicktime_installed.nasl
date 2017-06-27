#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21561);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"QuickTime for Windows Detection");
  script_summary(english:"Checks Windows registry for QuickTime");

  script_set_attribute(attribute:"synopsis", value:"There is a media player installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"QuickTime is installed on the remote host. QuickTime is a popular
media player / plug-in that handles various types of music and video
files.");
  script_set_attribute(attribute:"see_also", value:"http://www.apple.com/quicktime/");
  script_set_attribute(attribute:"solution", value:
"Make sure use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:quicktime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");
include("install_func.inc");


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


# Connect to the appropriate share.

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Determine where it's installed.
path = NULL;
key = "SOFTWARE\Apple Computer, Inc.\QuickTime";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}

# Ignore installs of QT Lite.
if (!isnull(path))
{
  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (!isnull(list))
  {
    key = NULL;
    foreach name (keys(list))
    {
      prod = list[name];
      if (prod && "QT Lite" >< prod)
      {
        key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
        key = str_replace(find:"/", replace:"\", string:key);


        key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
        if (!isnull(key_h))
        {
          item = RegQueryValue(handle:key_h, item:"InstallLocation");
          if (!isnull(item))
          {
            qtlite_path = item[1];
            qtlite_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:qtlite_path);

            if (tolower(qtlite_path) == tolower(path)) path = NULL;
          }
          RegCloseKey(handle:key_h);
        }

        if (isnull(path)) break;
      }
    }
  }
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# If it is...
ver = NULL;
ver_ui = NULL;
ver_ui2 = NULL;

if (path)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\QuickTimePlayer.exe", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    version = GetFileVersion(handle:fh);
    if ( ! isnull(version) ) ver = string(version[0], ".", version[1], ".", version[2], ".", version[3]);

    ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret)) children = ret['Children'];
    if (!isnull(children))
    {
      varfileinfo = children['VarFileInfo'];
      if (!isnull(varfileinfo))
      {
        translation =
          (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
          get_word (blob:varfileinfo['Translation'], pos:2);
        translation = tolower(display_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (!isnull(data))
        {
          ver_ui = data['FileVersion'];
          ver_ui2 = data['ProductVersion'];
        }
        else
        {
          data = stringfileinfo[toupper(translation)];
          if (!isnull(data))
          {
            ver_ui = data['FileVersion'];
            ver_ui2 = data['ProductVersion'];
          }
        }

        if (
          !isnull(ver_ui) && !isnull(ver_ui2) &&
          "(Dev)" >< ver_ui
        )
        {
          if ("QuickTime " >< ver_ui2) ver_ui2 = ver_ui2 - "QuickTime ";
          ver_ui = ver_ui2;
        }
      }
    }

    CloseFile(handle:fh);
  }
}
NetUseDel();


# Generate report and save info in KB.
if (path && ver)
{
  set_kb_item(name:"SMB/QuickTime/Version", value:ver);
  if (!isnull(ver_ui))
  {
    set_kb_item(name:"SMB/QuickTime/Version_UI", value:ver_ui);
    ver_report = ver_ui;
  }
  else ver_report = ver;
  set_kb_item(name:"SMB/QuickTime/Path",    value:path);

  register_install(
    app_name:"QuickTime for Windows",
    path:path,
    version:ver,
    display_version:ver_report,
    cpe:"cpe:/a:apple:quicktime");

  report = string(
    "\n",
    "  Version : ", ver_report, "\n",
    "  Path    : ", path, "\n"
  );
  security_note(port:port, extra:report);
}
