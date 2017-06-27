#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31852);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_name(english:"VLC Detection");
  script_summary(english:"Checks for VLC.");

  script_set_attribute(attribute:"synopsis", value:"There is a media player installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"VLC, a free and portable media player from the VideoLAN organization,
is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/vlc/");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of this program agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("install_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


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
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Check whether it's installed along with any of its plugins.
path = NULL;
plugins = make_array();
ver_reg = NULL;

key = "SOFTWARE\VideoLAN\VLC";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (isnull(item)) item = RegQueryValue(handle:key_h, item:"Install_Dir");
  if (!isnull(item)) path = item[1];

  item = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(item)) ver_reg = item[1];

  RegCloseKey(handle:key_h);
}

# - Firefox and friends.
key = "SOFTWARE\MozillaPlugins";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^@videolan\.org/vlc")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Path");
        if (!isnull(item))
        {
          file = item[1];
          plugins[file] = "Mozilla";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
# - ActiveX Control
key = "SOFTWARE\Classes\CLSID\{E23FE9C6-778E-49D4-B537-38FCDE4887D8}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
  {
    file = item[1];
    plugins[file] = "ActiveX";
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "VLC");
}

# Determine versions from various files.
info = "";
located = make_array(
  'vlc', FALSE,
  'Mozilla', FALSE,
  'ActiveX', FALSE
);

files = make_list(path+"\vlc.exe");
if (max_index(keys(plugins))) files = make_list(files, keys(plugins));
foreach file (files)
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
    file:file2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(fh))
  {
    ret = GetFileVersionEx(handle:fh);
    # nb: really old versions (eg, 0.4.6) don't support GetFileVersionEx()
    #     so just use the registry version.
    if (isnull(ret) && !located['vlc'])
    {
      if (file =~ "\\vlc\.exe$" && ver_reg)
      {
        kbkey = "SMB/VLC";
        info += '\n' +
                '  Product           : VLC\n' +
                '  Path              : ' + path + '\n' +
                '  Installed version : ' + ver_reg + '\n';
        set_kb_item(name:kbkey+"/File", value:file);
        set_kb_item(name:kbkey+"/Version", value:ver_reg);
        set_kb_item(name:kbkey+"/Path", value:path);

        register_install(
          app_name:"VLC media player",
          path:path,
          version:ver_reg,
          extra:make_array('File', file),
          cpe:"cpe:/a:videolan:vlc_media_player");

        located['vlc'] = TRUE;
      }
    }
    if (!isnull(ret)) children = ret['Children'];
    if (!isnull(children))
    {
      # nb: there's a problem using children['Translation'] to index into
      #     the StringFileInfo structure.
      stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo))
      {
        foreach key (keys(stringfileinfo))
        {
          data = stringfileinfo[key];
          if (!isnull(data))
          {
            ver = data['FileVersion'];
            if (!isnull(ver))
            {
              if (file =~ "\\vlc\.exe$" && !located['vlc'])
              {
                # Need to distinguish between 0.8.6g/h as a special case.
                if ("0.8.6g" == ver && ver_reg =~ "^0\.8\.6[hi]") ver = ver_reg;

                kbkey = "SMB/VLC";
                info += '\n' +
                        '  Product : VLC\n' +
                        '  Path    : ' + path + '\n' +
                        '  Version : ' + ver + '\n';
                register_install(
                  app_name:"VLC media player",
                  path:path,
                  version:ver,
                  extra:make_array('File', file),
                  cpe:"cpe:/a:videolan:vlc_media_player"
                );
                located['vlc'] = TRUE;
                set_kb_item(name:kbkey+"/Path", value:path);
              }
              else
              {
                variant = plugins[file];
                if (located[variant]) break;

                kbkey = "SMB/VLC/" + variant;

                info += '\n';
                if (variant == "Mozilla")
                  info += '  Component : Mozilla plugin\n';
                else if (variant == "ActiveX")
                  info += '  Component : ActiveX plugin\n';

                info += '  File      : ' + file + '\n';
                info += '  Version   : ' + ver + '\n';
                located[variant] = TRUE;
              }

              set_kb_item(name:kbkey+"/File", value:file);
              set_kb_item(name:kbkey+"/Version", value:ver);
              break;
            }
          }
        }
      }
    }
    CloseFile(handle:fh);
  }
  NetUseDel(close:FALSE);
}

# Find some plugins
plugin_path = path + "\plugins";
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:plugin_path);
dirpat = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\*", string:plugin_path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc == 1)
{
  kb_base = "SMB/VLC/plugin";
  retx = FindFirstFile(pattern:dirpat);

  while (!isnull(retx[1]))
  {
    if (retx[1] != "." && retx[1] != "..")
    {
      # 1.x has plugin DLLs in one dir
      if (retx[1] =~ "^.*\.dll")
        set_kb_item(name:kb_base, value: plugin_path+"\"+retx[1]);

      # 2.x has plugin DLLs in directories
      if (retx[2] >> 4 & 0x1) # FILE_ATTRIBUTE_DIRECTORY
      {
        # Search for the plugin DLLs in each directory
        dllpathpat = ereg_replace(
                       pattern:"^[A-Za-z]:(.*)",
                       replace:"\1\"+retx[1]+"\*",
                       string:plugin_path
                     );
        dll_retx = FindFirstFile(pattern:dllpathpat);

        while (!isnull(dll_retx[1]))
        {
          if ("_plugin.dll" >< dll_retx[1])
            set_kb_item(name:kb_base, value: plugin_path+"\"+retx[1]+"\"+dll_retx[1]);

          dll_retx = FindNextFile(handle:dll_retx);
        }
      }
    }
    retx = FindNextFile(handle:retx);
  }
}
NetUseDel();

# Report what we found.
if (info)
{
  set_kb_item(name:"SMB/VLC/installed" , value:TRUE);

  if (report_verbosity > 0)
  {
    # nb: info already has a leading '\n'.
    report = string(
    "\n",
      "Nessus found the following VLC components installed on\n",
      "the remote host :\n",
      info
    );
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
