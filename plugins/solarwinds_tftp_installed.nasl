#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47136);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_name(english:"SolarWinds TFTP Server Installed");
  script_summary(english:"Checks version of SolarWinds exe file");

  script_set_attribute(attribute:"synopsis", value:"A TFTP server is installed on the remote host.");
  script_set_attribute(attribute:"description", value:"SolarWinds TFTP Server is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.solarwinds.com/products/freetools/free_tftp_server.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:tftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated"))  exit(1,"The 'SMB/Registry/Enumerated' KB item is missing.");

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
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Find where it's installed.
path  = NULL;
paths = make_array();

# Location 1

key = "SYSTEM\CurrentControlSet\Services\SolarWinds TFTP Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"ImagePath");
  if (!isnull(value))
  {
    path = tolower(value[1]);
    # Get rid of double quotes, if any...
    if(path =~ '^\".*\"$')
      path = ereg_replace(pattern:'^\"(.+)\"$',string:path,replace:"\1");

    path = tolower(path);
    paths[path] = 1;

    path = NULL;
  }

  RegCloseKey(handle:key_h);
}

# Location 2, v9.x and later.

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  installstring = NULL;
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "SolarWinds TFTP Server" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      installstring = str_replace(find:"/", replace:"\", string:installstring);
      break;
    }
  }

  if(!isnull(installstring))
  {
    key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"InstallLocation");
      if (!isnull(value))
      {
        path = value[1];
        path = ereg_replace(string:path,pattern:"^([A-Za-z]:.+)",replace:"\1TFTPServer\SolarWinds TFTP Server.exe");
        path = tolower(path);
        # We only need unique install locations.
        # check if we already know this location.
        if(!paths[path])
          paths[path] = 1;

        path = NULL;
      }

      RegCloseKey(handle:key_h);
    }
  }
}

# Location 3,
# v9.x and later setup uninstall keys with identical display names as that of v8.x,
# This breaks location 2 check in 8.x. So look for a key that only exists in
# v8.x

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\SolarWinds TFTP Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"DisplayIcon");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(string:path,pattern:"^([A-Za-z]:.+)\SolarWinds.ico,-0$",replace:"\1tftp-s~1.exe");
    path = tolower(path);
    if(!paths[path])
      paths[path] = 1;

    path = NULL;
  }

  RegCloseKey(handle:key_h);
}

# Location 4

clsid = '';
key = "SOFTWARE\Classes\TFTP.Server\Clsid";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
    clsid = value[1];

  RegCloseKey(handle:key_h);
}

if(clsid)
{
  key = "SOFTWARE\Classes\CLSID\" + clsid +  "\LocalServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value))
    {
      path = tolower(value[1]);
      if(!paths[path])
        paths[path] = 1;

     path = NULL;
    }

    RegCloseKey(handle:key_h);
  }
}

RegCloseKey(handle:hklm);

info = '';

foreach loc (keys(paths))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:loc);
  exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:loc);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Cannot connect to " + share + "share.") ;
  }

  version  = NULL;
  product_name = NULL;
  company_name = NULL;

  fh = CreateFile(file:exe,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING);

  if (!isnull(fh))
  {
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
       translation = tolower(convert_dword(dword:translation, nox:TRUE));
      }
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        data = stringfileinfo[translation];
        if (isnull(data)) data = stringfileinfo[toupper(translation)];
        if (!isnull(data))
        {
          product_name = data['ProductName'];
          company_name = data['CompanyName'];
          version      = data['ProductVersion'];
        }
      }
    }

    CloseFile(handle:fh);

    if (
      !isnull(version) &&
      (
        (!isnull(product_name) && "SolarWinds" >< product_name) ||
        (!isnull(company_name) && "SolarWinds" >< company_name)
      )
    )
    {
      loc = ereg_replace(string:loc,pattern:"^([A-Za-z]:.+)\\[^\\]+$",replace:"\1");

      set_kb_item(name:"SMB/Solarwinds/tftp_server/Installed", value:TRUE);
      set_kb_item(name:"SMB/Solarwinds/tftp_server/"+version, value:loc);

      register_install(
        app_name:"SolarWinds TFTP Server",
        path:loc,
        version:version,
        cpe:"cpe:/a:solarwinds:tftp_server");

      info += '\n  Path    : ' + loc +
              '\n  Version : ' + version + '\n';
    }
  }
}

NetUseDel();

if(info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = "s of SolarWinds TFTP Server are";
    else s = " of SolarWinds TFTP Server is";

    report = '\n' +
      'The following instance' + s + ' installed :' + '\n' +
      info ;
    security_note(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_note(get_kb_item("SMB/transport"));
}
else
 exit(0,"SolarWinds TFTP Server is not installed on the remote host.");
