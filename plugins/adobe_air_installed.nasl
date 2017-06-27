#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32504);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/04/27 14:49:39 $");

  script_name(english:"Adobe AIR Detection");
  script_summary(english:"Checks for Adobe AIR and any RIAs");

  script_set_attribute(attribute:"synopsis", value:"A runtime environment is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Adobe AIR is installed on the remote host. It is a browser-
independent runtime environment that supports HTML, JavaScript, and
Flash code and provides for Rich Internet Applications (RIAs).");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/air.html");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of Adobe AIR itself and any associated RIAs agrees
with your organization's security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:air");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");
include("install_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");

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
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "TCP port "+port+" is closed.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "TCP connection failed to port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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

key = "SOFTWARE\Classes\AIR.InstallerPackage\shell\open\command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe.*$', replace:"\1", string:item[1], icase:TRUE);

  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Adobe AIR";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
      path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe.*$', replace:"\1", string:item[1], icase:TRUE);

    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Generate a list of installed apps.
app_names = make_array();
app_vers = make_array();
app_paths = make_array();

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey))
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"UninstallString");
        if (!isnull(item) && "Adobe AIR Application Installer.exe -uninstall" >< item[1])
        {
          item2 = RegQueryValue(handle:key2_h, item:"DisplayName");
          if (!isnull(item2)) app_names[subkey] = item2[1];

          item2 = RegQueryValue(handle:key2_h, item:"DisplayVersion");
          if (!isnull(item2)) app_vers[subkey] = item2[1];
          else app_vers[subkey] = "unknown";

          item2 = RegQueryValue(handle:key2_h, item:"InstallLocation");
          if (!isnull(item2))
          {
            app_paths[subkey] = item2[1];
            app_paths[subkey] = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:app_paths[subkey]);
          }
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
}
RegCloseKey(handle:hklm);


# Determine its version from one of the executables.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Adobe AIR Application Installer.exe", string:path);
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

version = NULL;
version_ui = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

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
      if (!isnull(data)) version_ui = data['ProductVersion'];
      else
      {
        data = stringfileinfo[toupper(translation)];
        if (!isnull(data)) version_ui = data['ProductVersion'];
      }
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();


# Save and report the version number and installation path of AIR as well as
# any associated RIAs.
if (!isnull(version) && !isnull(path))
{
  kb_base = "SMB/Adobe_AIR";
  set_kb_item(name:kb_base+"/Path", value:path);
  set_kb_item(name:kb_base+"/Version", value:version);

  register_install(
    app_name:"Adobe AIR",
    path:path,
    version:version,
    display_version:version_ui,
    cpe:"cpe:/a:adobe:air");
  if (!isnull(version_ui))
  {
    set_kb_item(name:kb_base+"/Version_UI", value:version_ui);
    version_report = version_ui;
  }
  else version_report = version;

  app_report = "";
  i = 0;
  max_apps = 25;
  foreach id (sort(keys(app_names)))
  {
    app_name = app_names[id];
    app_path = app_paths[id];
    app_ver  = app_vers[id];

    set_kb_item(name:kb_base+"/"+app_name+"/Path", value:app_path);
    set_kb_item(name:kb_base+"/"+app_name+"/Version", value:app_ver);

    if (++i <= max_apps || thorough_tests)
    {
      app_report += '    ' + app_name + '\n' +
                    '      Version      : ' + app_ver + '\n' +
                    '      Path         : ' + app_path + '\n' +
                    '\n';
    }
  }
  if (i > max_apps && !thorough_tests)
  {
    app_report = string(
      app_report,
      "\n",
      "Note that only the first ", max_apps, " applications are listed in this report.\n",
      "For a complete audit, edit the scan policy, enable the 'Perform\n",
      "thorough tests' setting and re-run the scan.\n"
    );
  }

  if (report_verbosity)
  {
    if (report_verbosity > 1)
    {
      report = string(
        "\n",
        "  Version          : ", version_report, "\n",
        "  Path             : ", path, "\n",
        "\n",
        "  AIR Applications : \n",
        app_report
      );
    }
    else
    {
      report = string(
        "\n",
        "  Version : ", version_report, "\n",
        "  Path    : ", path, "\n"
      );
    }
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
