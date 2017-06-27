#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(52715);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/04 23:59:59 $");

  script_name(english:"TeamViewer Version Detection");
  script_summary(english:"Checks for TeamViewer");

  script_set_attribute(attribute:"synopsis", value:
"A remote control service is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"TeamViewer, a remote control service, is installed on the remote
Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.teamviewer.com/en/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/18");
  
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_set_attribute(attribute:"plugin_type", value:"local");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
app = 'TeamViewer';
paths = make_list();
version = NULL;
installs = 0;

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\TeamViewer\";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (isnull(key_h)) audit(AUDIT_NOT_INST, app);

path = RegQueryValue(handle:key_h, item:"InstallationDirectory");
if (!empty_or_null(path))
{
  paths = make_list(paths, path[1]);
  installs++;
}
# Older versions use a Version# subkey, and may have multiple installs
info = RegQueryInfoKey(handle:key_h);
for (i = 0; i < info[1]; ++i)
{
  subkey = RegEnumKey(handle:key_h, index:i);
  pat = '^Version[0-9\\.]+';

  if (strlen(subkey) && preg(pattern:pat, string:subkey))
  {
    key2 = key + '\\' + subkey;
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      value = RegQueryValue(handle:key2_h, item:"InstallationDirectory");
      if (!empty_or_null(value))
      {
        paths = make_list(paths, value[1]);
        installs++;
      }
      RegCloseKey(handle:key2_h);
    }
  }
}

RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);

if (!installs) audit(AUDIT_NOT_INST, app);

foreach path (paths)
{
  exe = hotfix_append_path(path:path, value:"TeamViewer.exe");

  bin_installed = hotfix_file_exists(path:exe);
  if ( empty_or_null(bin_installed) || !bin_installed ) continue;

  version = hotfix_get_pversion(path:exe);

  err = hotfix_handle_error(
    error_code  : version['error'],
    file        : exe,
    appname     : app,
    exit_on_fail: TRUE
  );

  version = join(version['value'], sep:'.');

  set_kb_item(name:"SMB/TeamViewer/"+version, value:path);

  register_install(
    app_name:app,
    path:path,
    version:version,
    cpe:"cpe:/a:teamviewer:teamviewer"
  );

}

set_kb_item(name:"SMB/TeamViewer/Installed", value:"TRUE");

report_installs(app_name:app);
