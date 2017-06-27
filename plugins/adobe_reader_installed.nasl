#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(20836);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/03/10 21:03:23 $");

  script_name(english:"Adobe Reader Detection");
  script_summary(english:"Checks for Adobe Reader");

 script_set_attribute(attribute:"synopsis", value:"There is a PDF file viewer installed on the remote Windows host.");
 script_set_attribute(attribute:"description", value:"Adobe Reader, a PDF file viewer, is installed on the remote host.");
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/reader/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/02");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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


function getDisplayVersion(pattern, version)
{
  local_var version_ui = "";
  local_var v = eregmatch(pattern:pattern, string:version);
  if (!isnull(v))
  {
    if (ver[0] < 7)
    {
      version_ui = v[1] + " " + int(v[3]) + "/" + int(v[4]) + "/" + int(v[2]);
    }
    else
    {
      version_ui = v[1];
    }
  }
  else version_ui = version;

  return version_ui;
}

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


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


# Determine where it's installed.
path = NULL;
min = NULL;
max = NULL;

# A little workaround to make sure info is read from the registry correctly on 64-bit
# Windows
if (get_kb_item("SMB/WoW"))
  key = "SOFTWARE\Wow6432Node\Adobe\Acrobat Reader";
else
  key = "SOFTWARE\Adobe\Acrobat Reader";

paths = make_list();
mins = make_array();
maxs = make_array();

# - nb: this works for recent versions of Adobe Reader.
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    path = NULL;
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$" || subkey == "DC")
    {
      key2 = key + "\" + subkey + "\InstallPath";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        install_info = RegQueryValue(handle:key2_h);
        if (!isnull(install_info)) path = install_info[1];
        RegCloseKey(handle:key2_h);
      }

      if (isnull(path)) continue;
      else paths = make_list(paths, path);

      key2 = key + "\" + subkey + "\Installer";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"VersionMax");
        if (!isnull(value)) maxs[path] = int(value[1]);

        value = RegQueryValue(handle:key2_h, item:"VersionMin");
        if (!isnull(value)) mins[path] = int(value[1]);

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  NetUseDel();
  exit(0, 'Adobe Reader was not detected on this host.');
}
else NetUseDel(close:FALSE);

info = NULL;
installs = 0;

foreach path (paths)
{
  # Determine its version from the executable itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\AcroRd32.exe", string:path);

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
  version = NULL;
  if (!isnull(fh))
  {
    version = GetProductVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # In some versions of Reader, the version is only updated in the
  # AcroRd32.dll (not exe). So, let's save the DLL version off
  # and let the dependent plugin decide which version to use.

  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\AcroRd32.dll", string:path);
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  dll_version = "";
  if (!isnull(fh))
  {
    dll_version = GetProductVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # Get the version from AcroRd32.dll for versions 7.x ,8.1.x, 11.0.4.x
  if (version =~ "^(7\.0\.8\.|8\.1\.0\.|11\.0\.04)")
    version = dll_version;

  if (isnull(version))
  {
    NetUseDel(close:FALSE);
    continue;
  }

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Handle version changes in updates.
  max = maxs[path];
  min = mins[path];
  if (!isnull(max) && !isnull(min))
  {
    a = (max >> 16);
    b = max & 0xffff;
    c = min >> 16;
    d = min & 0xffff;

    if (ver[0] > 7 && ver[0] == a && ver[1] == b && ver[2] < c)
    {
      ver[2] = c;
      ver[3] = d;
      version = ver[0] + "." + ver[1] + "." + ver[2];
    }
    if (ver[0] <= 7 && a == 0 && ver[0] == b && ver[1] == c && ver[2] < d)
    {
      ver[2] = d;
      ver[3] = 0;
      version = ver[0] + "." + ver[1] + "." + ver[2];
    }
  }

  # Reformat the version based on how it's displayed in
  # the Help, About menu pull-down.
  pat = "^([0-9]+\.[0-9]+\.[0-9])\.(2[0-9]{3})([0-9]{2})([0-9]{2})([0-9]{2})$";
  version_ui = getDisplayVersion(pattern:pat, version:version);
  dll_version_ui = getDisplayVersion(pattern:pat, version:dll_version); 

  set_kb_item(name:"SMB/Acroread/Version", value:version);
  set_kb_item(name:"SMB/Acroread/"+version+"/Path", value:path);
  set_kb_item(name:"SMB/Acroread/"+version+"/Version_UI", value:version_ui);

  extras = make_array(
    'DLL_Product_Version', dll_version,
    'DLL_Display_Version', dll_version_ui
  );

  register_install(
    app_name:"Adobe Reader",
    path:path,
    version:version,
    display_version:version_ui,
    cpe:"cpe:/a:adobe:acrobat_reader",
    extra_no_report:extras);

  installs++;
  info += '\nPath    : '+path+
          '\nVersion : '+version_ui+'\n';

  NetUseDel(close:FALSE);
}
NetUseDel();

if (installs == 0) exit(0, 'Adobe Reader was not detected on this host.');

if (report_verbosity > 0)
{
  if (installs == 1) s = ' ';
  else s = 's ';
  report = '\nNessus discovered the following installation'+s+'of Adobe Reader :\n'+info;
  security_note(port:port, extra:report);
}
else security_note(port);
