#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43860);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/10/10 20:53:10 $");

  script_name(english:"Adobe Illustrator Detection");
  script_summary(english:"Checks for Adobe Illustrator.");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Corporation's Illustrator software is installed on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"Adobe Corporation's Illustrator software, a vector graphics editing
tool, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/illustrator/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:illustrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

# Connect to the appropriate share
get_kb_item_or_exit('SMB/Registry/Enumerated');


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

prod = NULL;

name   = kb_smb_name();
port   = kb_smb_transport();
#if (!get_port_state(port)) exit(0, 'Port '+port+' is not open.');
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

#Connect to remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

path=NULL;

#Look for the Path in the \Windows\CurrentVersion\App Paths registry
key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\Illustrator.exe';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}

# If we couldn't find the path that way...
# Look for Adobe Bridge,  which should be installed in the same base directory.
if (isnull(path))
{
  key = 'SOFTWARE\\Adobe\\Adobe Bridge';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey) && subkey =~ "^CS[0-9]+$")
      {
        key2 = key + "\"+subkey+"\Installer";
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h, item:"InstallPath");
          if (!isnull(value)) path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Adobe Bridge CS([0-9])", replace:"\1\Adobe Illustrator CS\2", string:value[1]);
          path = path+"\Support Files\Contents\Windows";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, "Adobe Illustrator does not appear to be installed.");
}

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Illustrator.exe", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '" + share + "'share.");
}

fh = CreateFile(
       file:file,
       desired_access:GENERIC_READ,
       file_attributes:FILE_ATTRIBUTE_NORMAL,
       share_mode:FILE_SHARE_READ,
       create_disposition:OPEN_EXISTING
     );

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);

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
    # nb: if varfileinfo is missing, use the first key for the translation.
    if (isnull(varfileinfo) && !isnull(stringfileinfo))
    {
      foreach translation (keys(stringfileinfo))
        break;
    }
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) prod = data['ProductName'];
      else
      {
        data = stringfileinfo[toupper(translation)];
        if (!isnull(data)) prod = data['ProductName'];
      }
    }
  }
  timestamp = ret['dwTimeDateStamp'];
  CloseFile(handle:fh);

  if (!isnull(ver) && !isnull(prod))
  {
    version = ver[0] + "." + ver[1] + "." + ver[2];
    version_ui = ver[0] + "." + ver[1] + " Build " + ver[2];
    set_kb_item(name:"SMB/Adobe Illustrator/Installed", value:TRUE);
    set_kb_item(name:"SMB/Adobe Illustrator/product", value:prod);
    set_kb_item(name:"SMB/Adobe Illustrator/path", value:path);
    set_kb_item(name:"SMB/Adobe Illustrator/version", value:version);
    set_kb_item(name:"SMB/Adobe Illustrator/version_ui", value:version_ui);

    extra = make_array("product", prod);

    if (!isnull(timestamp))
    {
      set_kb_item(name:"SMB/Adobe Illustrator/timestamp", value:timestamp);
      extra['Timestamp'] = timestamp;
    }
    register_install(
      app_name:"Adobe Illustrator",
      path:path,
      version:version,
      display_version:version_ui,
      extra:extra,
      cpe:"cpe:/a:adobe:illustrator");

    if (report_verbosity > 0)
    {
       report =
        '\n  Application  : ' + prod +
        '\n  Path         : ' + path +
        '\n  Version      : ' + version_ui +
        '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port:port);
  }
}
NetUseDel();
