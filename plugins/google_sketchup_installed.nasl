#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56712);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_name(english:"Google/Trimble SketchUp Detection");
  script_summary(english:"Checks for Google/Trimble SketchUp install");

  script_set_attribute(attribute:"synopsis", value:
"There is a 3-D modeling application installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Google SketchUp or Trimble SketchUp (formerly Google SketchUp) is
installed on the remote host. SketchUp is a 3-D modeling application.");
  script_set_attribute(attribute:"see_also", value:"http://sketchup.google.com/");
  script_set_attribute(attribute:"see_also", value:"http://www.sketchup.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:sketchup");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

# Version UI matchups (actually to release notes)
ver_ui_arr = make_array(
  "13.0.4124",  "2013 Maintenance 1",
  "13.0.3689",  "2013",
  "8.0.16846",  "8.0 Maintenance 5",  # 19 DEC 2012
  "8.0.15158",  "8.0 Maintenance 4",  # 28 AUG 2012
  "8.0.14346",  "8.0 Maintenance 3",
  "8.0.11752",  "8.0 Maintenance 2",
  "8.0.4811",   "8.0 Maintenance 1",
  "8.0.3117",   "8.0",
  "7.1.6860",   "7.1 Maintenance 2",
  "7.1.6087",   "7.1 Maintenance 1",
  "7.1.4871",   "7.1",
  "7.0.10247",  "7.0 Maintenance 1",
  "7.0.8657",   "7.0",
  "6.4.265",    "6.4 Maintenance 6"
);
# older versions don't use this scheme

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) audit(AUDIT_SOCK_FAIL, port);

# Connect to IPC share on machine
#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to registry on machine
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

sketchup_installs = make_array();

keys_and_subkeys = make_array(
  'SOFTWARE\\Google', "google.*sketchup",
  'SOFTWARE\\SketchUp', "sketchup 20[0-9][0-9]" # For now only 2013 exists
);

foreach key (keys(keys_and_subkeys))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    if (isnull(info))
    {
      RegCloseKey(handle:key_h);
      continue;
    }

    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (tolower(subkey) =~ keys_and_subkeys[key])
      {
        key2 = key + '\\' + subkey + '\\InstallLocation';
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h);
          if (!isnull(value)) sketchup_installs[subkey] = value[1];
          RegCloseKey(handle:key2_h);
        }

        # For Trimble differentiate between Make and Pro family
        if ("google" >!< tolower(subkey))
        {
          key3 = key + '\\' + subkey;
          key3_h = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
          if (!isnull(key3_h))
          {
            value = RegQueryValue(handle:key3_h, item:"ProductFamily");
            if (!isnull(value)) trimble_sketchup_family = value[1];
            RegCloseKey(handle:key3_h);
          }
        }
      }
    }
    RegCloseKey(handle:key_h);
  }
}

# Also look in Uninstall for early SketchUp (6.x and below)
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && prod =~ "^Google SketchUp( (Pro)?[0-9.]+)?$")
    {
      key = ereg_replace(pattern:"\/DisplayName$", replace:"", string:name);
      key = str_replace(find:"/", replace:"\", string:key);
      key = key - "SMB\Registry\HKLM\";
    }
    else continue;

    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"InstallLocation");
      if (!isnull(value)) sketchup_installs[prod] = value[1];
      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);

if (max_index(keys(sketchup_installs)) == 0)
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Google SketchUp and Trimble SketchUp");
}

report = "";

foreach install (keys(sketchup_installs))
{
  NetUseDel(close:FALSE);

  display_name = install;

  # Differentiate between Google and Trimble
  if ("google" >< tolower(display_name))
    vendor = "Google";
  else
    vendor = "Trimble";

  path = sketchup_installs[install];
  path = ereg_replace(pattern:"(.*)\\$", replace:"\1", string:path);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }
  exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SketchUp.exe", string:path);
  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    filever = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    if (!isnull(filever))
    {
      ver = join(filever, sep:'.');

      set_kb_item(name:"SMB/"+vendor+"_SketchUp/"+ver, value:path);
      set_kb_item(name:"SMB/"+vendor+"_SketchUp/"+ver+"/Name", value:display_name);

      version_ui = ver_ui_arr[filever[0] + "." + filever[1] + "." + filever[2]];
      if (isnull(version_ui))
        version_ui = filever[0] + "." + filever[1] + "." + filever[2];

      set_kb_item(name:"SMB/"+vendor+"_SketchUp/"+ver+"/Version_UI", value:version_ui);

      if (vendor == "Trimble")
      {
        display_name = "Trimble " + display_name + " (" + trimble_sketchup_family + ")";
        set_kb_item(name:"SMB/"+vendor+"_SketchUp/"+ver+"/ProductFamily", value:trimble_sketchup_family);
      }

      register_install(
        app_name:"Google SketchUp and Trimble SketchUp",
        path:path,
        version:ver,
        display_version:version_ui,
        extra:make_array("Display Name", display_name),
        cpe:"cpe:/a:google:sketchup");

      report += '\n' +
      "  Product : " + display_name + '\n' +
      "  Path    : " + path + '\n' +
      "  Version : " + version_ui + '\n';
    }
  }
}

# Cleanup
NetUseDel();

if (report)
{
  set_kb_item(name:"SMB/"+vendor+"_SketchUp/Installed", value:TRUE);
  if (report_verbosity > 0) security_note(port:port,extra:report);
  else security_note(port);
}
else audit(AUDIT_NOT_INST, "Google SketchUp and Trimble SketchUp");
