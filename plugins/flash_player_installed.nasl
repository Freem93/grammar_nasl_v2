#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28211);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_name(english:"Flash Player Detection");
  script_summary(english:"Checks for Flash Player");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser enhancement for displaying
multimedia content.");
  script_set_attribute(attribute:"description", value:
"There is at least one instance of Adobe Flash Player installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/flashplayer/");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:flash_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "opera_installed.nasl", "google_chrome_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

function list_subdir(basedir)
{
  local_var subdirs, retx, share, dirpat, rc;
  subdirs = make_list();

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:basedir);
  dirpat = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\*", string:basedir);

  rc = NetUseAdd(share:share);
  if (rc != 1)
  {
    NetUseDel();
    return NULL;
  }
  else
  {
    retx = FindFirstFile(pattern:dirpat);
    while (!isnull(retx[1]))
    {
      if ("." != retx[1] && ".." != retx[1] && ".ini" >!< retx[1])
      {
        subdirs = make_list(subdirs, retx[1]);
      }
      retx = FindNextFile(handle:retx);
    }
    if(max_index(subdirs) > 0) return subdirs;
    else return NULL;
  }
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


# Check whether it's installed.
variants = make_array();
# - check for the browser plugin.
key = "SOFTWARE\MozillaPlugins\@adobe.com/FlashPlayer";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
  {
    file = item[1];
    variants[file] = "Plugin";
  }
  RegCloseKey(handle:key_h);
}
key = "SOFTWARE\Mozilla";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Mozilla Firefox ")
    {
      key2 = key + "\" + subkey + "\Extensions";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Plugins");
        if (!isnull(item))
        {
          file = item[1] + "\NPSWF32.dll";
          variants[file] = "Plugin";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
opera_path = get_kb_item("SMB/Opera/Path");
if (!isnull(opera_path))
{
  # nb: we'll check later whether this actually exists.
  file = opera_path + "\Program\Plugins\NPSWF32.dll";
  variants[file] = "Plugin";
}
# - check for the ActiveX control.
key = "SOFTWARE\Classes\CLSID\{D27CDB6E-AE6D-11cf-96B8-444553540000}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
  {
    file = item[1];
    variants[file] = "ActiveX";
  }
  RegCloseKey(handle:key_h);
}

# Chrome
chrome_installs = get_kb_list("SMB/Google_Chrome/*");
chrome_installs = NULL;
if (!isnull(chrome_installs))
{
  if (thorough_tests)
  {
    # Find out where user directories are stored.
    key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    if (isnull(hklm))
    {
      NetUseDel();
      exit(0);
    }

    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

    if (!isnull(key_h))
    {
      item = RegQueryValue(handle:key_h, item:"ProfilesDirectory");
      if (!isnull(item)) pdir = item[1];
      RegCloseKey(handle:key_h);
    }

    if (pdir && stridx(tolower(pdir), "%systemdrive%") == 0)
    {
      key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        item = RegQueryValue(handle:key_h, item:"SystemRoot");
        if (!isnull(item))
        {
          winroot = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1:", string:item[1]);
          pdir = winroot + substr(pdir, strlen("%systemdrive%"));
        }
        RegCloseKey(handle:key_h);
      }
    }
    if (pdir)
    {
      # Get OS ver
      windows_version = get_kb_item("SMB/WindowsVersion");

      pepperPaths = make_list();
      subDirs = list_subdir(basedir:pdir);
      foreach subdir (subDirs)
      {
        path = pdir + "\" + subdir;
        # 2k / 2k3 / XP
        if (windows_version < 6 ) chrome_profile = path + "\Local Settings\Application Data\Google\Chrome\User Data\PepperFlash\";
        # Vista / Win 7 / 2k8
        else chrome_profile =  path + "\appdata\Local\Google\chrome\User Data\PepperFlash\";

        pepper_vers = list_subdir(basedir:chrome_profile);
        foreach pepper_ver (pepper_vers)
        {
          file = chrome_profile + pepper_ver + "\pepflashplayer.dll";
          variants[file] = "Chrome_Pepper";
        }
      }
    }
  }
  foreach chrome_install (keys(chrome_installs))
  {
    if ("Installed" >< chrome_install) continue;


    chrome_path = chrome_installs[chrome_install];
    item = eregmatch(string:chrome_install, pattern:"^SMB.*\/([0-9\.]+)([^0-9]|$)");
    version = item[1];

    # For Win Vista / 7
    chrome_path = ereg_replace(
      string:chrome_path,
      pattern:"^([A-Za-z]:\\Users\\[^\\]+).*",
      replace:"\1\AppData\Local\Google\Chrome\Application"
    );

    # For Chrome earlier than 21.x look for instances of gcswf32.dll
    # For Chrome 21.x or later, we have to look at the Pepperflash version
    # nb: we'll check later whether this actually exists.
    chrome_vers = split(version, sep:'.', keep:FALSE);
    if (chrome_vers[0] < 21)
    {
      file = chrome_path + "\" + version + "\gcswf32.dll";
      variants[file] = "Chrome";
    }
    else
    {
      file = chrome_path + "\" + version + "\PepperFlash\pepflashplayer.dll";
      variants[file] = "Chrome_Pepper";
    }
  }
}
RegCloseKey(handle:hklm);

if (max_index(keys(variants)) == 0)
{
  NetUseDel();
  exit(0);
}

# Determine the version of each instance found.
counts["Plugin"] = 0;
counts["ActiveX"] = 0;
counts["Chrome"] = 0;
counts["Chrome_Pepper"] = 0;
info = "";

foreach file (keys(variants))
{
  variant = variants[file];
  version = NULL;

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  # For reporting purposes, we are showing pepflashplayer.dll
  # The version comes from manifest.json
  if ('pepflashplayer.dll' >< file2)
    file2 = str_replace(string:file2, find:'pepflashplayer.dll', replace:'manifest.json');
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:file2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    counts[variant]++;
    if (variant != "Chrome_Pepper")
    {
      ver = GetFileVersion(handle:fh);
      if (!isnull(ver))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      }
    }
    else
    {
      fsize = GetFileSize(handle:fh);
      if (fsize > 10240) fsize = 10420;
      if (fsize)
      {
        data = ReadFile(handle:fh, length:fsize, offset:0);
        CloseFile(handle:fh);
        if (!isnull(data))
        {
          idx_start = stridx(data, '"version"');
          data = substr(data, idx_start);
          idx_end = stridx(data, ",");
          data = substr(data, 0, idx_end);
          data = data - '"version": "';
          data = data - '",';
          data = chomp(data);

          if (data =~ '^[0-9\\.]+$')
            version = data;
        }
      }
    }
    CloseFile(handle:fh);
  }
  if (version)
  {
    if (variant == "Plugin")
    {
      info += '  - Browser Plugin (for Firefox / Netscape / Opera) :\n';
    }
    else if (variant == "ActiveX")
    {
      info += '  - ActiveX control (for Internet Explorer) :\n';
    }
    else if (variant == "Chrome" || variant == "Chrome_Pepper")
    {
      info += '  - Browser Plugin (for Google Chrome) :\n';
    }

    info += '    ' + file + ', ' + version + '\n';

    set_kb_item(name:"SMB/Flash_Player/"+variant+"/File/"+counts[variant], value:file);
    set_kb_item(name:"SMB/Flash_Player/"+variant+"/Version/"+counts[variant] , value:version);
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


# Issue a report.
if (info)
{
  set_kb_item(name:"SMB/Flash_Player/installed" , value:TRUE);

  report = string(
    "Nessus found the following instances of Flash Player installed on the\n",
    "remote host :\n",
    "\n",
    info
  );
  security_note(port:kb_smb_transport(), extra:report);
}
