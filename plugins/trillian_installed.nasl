#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11428);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"Trillian Detection");
  script_summary(english:"Checks for Trillian");

 script_set_attribute(attribute:"synopsis", value:
"There is an instant messaging application installed on the remote
Windows host.");
 script_set_attribute(attribute:"description", value:
"Trillian is installed on the remote Windows host. Trillian is an
instant messaging client for Windows.");
 script_set_attribute(attribute:"see_also", value:"http://www.ceruleanstudios.com/learn/");
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/21");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:trillian:trillian");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

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
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

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
  exit(0);
}


# Find the path if it's installed.
path = NULL;

key = "SOFTWARE\Clients\IM\Trillian\InstallInfo";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ReinstallCommand");
  if (!isnull(value))
    path = ereg_replace(pattern:'"(.+\\trillian\\.exe)".*', replace:"\1", string:value[1]);

  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  key = "SOFTWARE\Classes\Trillian.SkinZip\shell\Add\command";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value))
      path = ereg_replace(pattern:'"(.+\\trillian\\.exe)".*', replace:"\1", string:value[1]);

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);
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
if (!isnull(fh))
{
  ver = NULL;

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
      translation = toupper(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[tolower(translation)];
      if (!isnull(data)) ver = data['ProductVersion'];
    }
  }
  CloseFile(handle:fh);

  # If the version number's available, save and report it.
  if (!isnull(ver))
  {
    path = ereg_replace(pattern:"\\trillian\.exe", replace:"", string:path);
    ver = ereg_replace(pattern:", +", replace:".", string:ver);

    set_kb_item(name:"SMB/Trillian/Version",  value:ver);
    set_kb_item(name:"SMB/Trillian/Path",     value:path);

    register_install(
      app_name:"Trillian",
      path:path,
      version:ver,
      cpe:"cpe:/a:trillian:trillian");

    report = string(
      "  Version : ", ver, "\n",
      "  Path    : ", path, "\n"
    );
    security_note(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
