#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(60110);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"FlashFXP Detection");
  script_summary(english:"Detects installs of FlashFXP");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an FTP client.");
  script_set_attribute(attribute:"description", value:"The remote Windows host has FlashFXP, an FTP client, installed on it.");
  script_set_attribute(attribute:"see_also", value:"http://www.flashfxp.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:flashfxp:flashfxp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

port = kb_smb_transport();
appname = 'FlashFXP';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\FlashFXP";
subkeys = get_registry_subkeys(handle:hklm, key:key);

paths = make_list();

# will pickup 3.x and 4.x installs
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + "\Install Path";
    path = get_registry_value(handle:hklm, item:entry);
    if (!isnull(path))
      paths = make_list(paths, path);
  }
}

# Will pick up 2.x install
# 2.x installs only write "Uninstall" keys to the registry
# C:\PROGRA~1\FlashFXP\UNWISE.EXE C:\PROGRA~1\FlashFXP\INSTALL.LOG
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\FlashFXP\UninstallString";
path = get_registry_value(handle:hklm, item:key);
uninstall_path = NULL;
if(!isnull(path))
{
  item = eregmatch(pattern:"(.*)\\UNWISE.EXE .*", string:path);
  if(!isnull(item[1]))
    paths = make_list(paths, item[1]);
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

installs = make_array();
validatedinstall = FALSE;
foreach path(paths)
{
  exe = path + "\FlashFXP.exe";
  ver = hotfix_get_fversion(path:exe);
  if (!isnull(ver['value']))
  {
    validatedinstall = TRUE;
    str_ver = join(sep:'.', ver['value']);
    installs[path] = str_ver;
  }
}

# check for 2.x install
if(!isnull(uninstall_path))
{
  exe = uninstall_path + "\FlashFXP.exe";
  ver = hotfix_get_fversion(path:exe);
  str_ver = join(sep:'.', ver['value']);
  # just to prevent double reports
  # 3.x and 4.x installs will be found by code above
  if(str_ver =~ "^[12]\.")
  {
    validatedinstall = TRUE;
    installs[uninstall_path] = str_ver;
  }
}

hotfix_check_fversion_end();

if (!validatedinstall)
  audit(AUDIT_UNINST, appname);

kb_base = 'SMB/FlashFXP/';
set_kb_item(name:kb_base+'Installed', value:TRUE);

report = '';
foreach path (keys(installs))
{
  set_kb_item(name:kb_base+'Installs/'+installs[path], value:path);

  register_install(
    app_name:appname,
    path:path,
    version:installs[path],
    cpe:"cpe:/a:flashfxp:flashfxp");

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + installs[path] + '\n';
}

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
