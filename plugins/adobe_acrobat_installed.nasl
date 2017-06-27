#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40797);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/04/12 18:37:27 $");

  script_name(english:"Adobe Acrobat Detection");
  script_summary(english:"Checks for Adobe Acrobat.");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Acrobat is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Adobe Acrobat, a PDF file creation and editing tool, is installed on
the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://acrobat.adobe.com/us/en/acrobat.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

# Connect to the appropriate share.
get_kb_item_or_exit('SMB/Registry/Enumerated');
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
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
min = NULL;
max = NULL;

# - nb: this works for recent versions of Adobe Acrobat.
key = 'SOFTWARE\\Adobe\\Adobe Acrobat';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && (subkey =~ "^[0-9.]+$" || subkey == "DC"))
    {
      key2 = key + '\\' + subkey + '\\';
      if(subkey !~ "^20\d\d$" && subkey != "DC")
        key2 = key2 + 'Installer';
      else
        key2 = key2 + 'InstallPath';
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"VersionMax");
        if (!isnull(value)) max = int(value[1]);

        value = RegQueryValue(handle:key2_h, item:"VersionMin");
        if (!isnull(value)) min = int(value[1]);

        value = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(value)) path = ereg_replace(pattern:"^(.+)\\$", replace:'\\1', string:value[1]);

        # Alternate Install Path key, trailing '\' to get default
        # Only applies to 2015+
        if(subkey =~ "^20\d\d$" || subkey == "DC")
        {
          value = RegQueryValue(handle:key2_h, item:NULL);
          if (!isnull(value)) path = ereg_replace(pattern:"^(.+)\\Acrobat$", replace:'\\1', string:value[1]);
        }

        if ( ( subkey == '8.0' ) && ( min >> 16 == 2 ) )
        {
          value = RegQueryValue(handle:key2_h, item:'VersionSU');
          if ( !isnull(value) )
          {
            su1 = value[ 1 ];
            set_kb_item(name:"SMB/Acrobat/812su1Installed", value:su1 );
          }
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}

# Loop over the registry to get the version number
key = '';
display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (!isnull(display_names))
{
  foreach val (keys(display_names))
  {
    display_name = display_names[val];
    if ('Adobe Acrobat' >< display_name && 'Reader' >!< display_name)
    {
      val = val - 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/' - '/DisplayName';
      key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" + '\\' + val;
      break;
    }
  }
}

if (key)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Version");
    if (!isnull(item))
    {
      if (item[1] =~ '^[0-9]+$')
      {
        value = int(item[1]);

        regversion = ((value >>> 24) & 0xFF) + '.' +
                  ((value >>> 16) & 0xFF) + '.' +
                  (value & 0xFFFF);
      }
    }
  }
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, 'No evidence of Acrobat found in the registry.' );
}
NetUseDel(close:FALSE);

# Determine its version from the executable itself.
share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
exe =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\Acrobat\\Acrobat.exe', string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

# Grab the version number if the file was opened successfully.  Otherwise,
# bail out.
version = '';
if ( fh )
{
  version = GetProductVersion(handle:fh);
  CloseFile(handle:fh);
}
else
{
  NetUseDel();
  exit(1, "Unable to access the Acrobat executable : " + exe);
}

# For versions 10.x and later, use the version from the registry
if (version !~ '^([0-9])\\.' && !isnull(regversion))
{
  ver = split(version, sep:'.');
  regver = split(regversion, sep:'.');
  # Make sure the major value for the registry version is the
  # same as the major value for the file version
  if (regver[0] == ver[0])
    version = regversion;
}
# For some reason, the product version of acrobat.exe 7.1.0 drops back to 7.0.8.
# so check Distillr\\acrodist.exe for the product version.
else if (version =~ "^7\.0\.8\.")
{
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:'\\1\\Distillr\\acrodist.exe', string:path);
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  version = '';
  if ( fh )
  {
    version = GetProductVersion(handle:fh);
    CloseFile(handle:fh);
  }
  else
  {
    NetUseDel();
    exit(1, "Unable to access Acrobat executable : " + dll);
  }
}
# Acrobat.exe does not seem to update when upgrading from 11.0.4 to 11.0.5
# so check Acrobat.dll for the correct version
else if (version =~ "^11\.0\.04\.")
{
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:'\\1\\Acrobat\\Acrobat.dll', string:path);
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  version = '';
  if ( fh )
  {
    version = GetProductVersion(handle:fh);
    CloseFile(handle:fh);
  }
  else
  {
    NetUseDel();
    exit(1, "Unable to access Acrobat DLL : " + dll);
  }
}
NetUseDel();

# Save and report the version number and installation path.
if (!isnull(version) && !isnull(path))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  # Handle version changes in updates.
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
  v = eregmatch(pattern:pat, string:version);
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

  set_kb_item(name:"SMB/Acrobat/Path", value:path);
  set_kb_item(name:"SMB/Acrobat/"+version+"/Path", value:path);
  set_kb_item(name:"SMB/Acrobat/Version", value:version);
  set_kb_item(name:"SMB/Acrobat/Version_UI", value:version_ui);

  register_install(
    app_name:"Adobe Acrobat",
    path:path,
    version:version,
    display_version:version_ui,
    extra:make_array("812su1Installed", su1),
    cpe:"cpe:/a:adobe:acrobat");

  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '  Product : Adobe Acrobat\n' +
      '  Path    : '+ path+ '\n' +
      '  Version : '+ version_ui+ '\n';

    if ( su1 )
      report += '  Update  : Security Update 1 \n';

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
