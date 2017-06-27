#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65985);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/07 18:43:41 $");

  script_name(english:"Lenovo ThinkPad Bluetooth with Enhanced Data Rate Detection");
  script_summary(english:"Detects version of Lenovo ThinkPad Bluetooth with Enhanced Data Rate");

  script_set_attribute(attribute:"synopsis", value:"The remote host has Bluetooth management software installed.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has Lenovo ThinkPad Bluetooth with Enhanced Data Rate
installed, a set of drivers and tools for managing Bluetooth
connections on Lenovo ThinkPad computers."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lenovo:thinkpad_bluetooth_with_enhanced_data_rate_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'Lenovo ThinkPad Bluetooth with Enhanced Data Rate Software';
kb_base = "SMB/Lenovo_BT_EDR/";

port = kb_smb_transport();

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1, "The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall' KB items are missing.");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = NULL;

foreach name (keys(list))
{
  prod = list[name];
  if (
    prod &&
    ('ThinkPad' >< prod || 'Lenovo' >< prod) &&
    'Bluetooth with Enhanced Data Rate Software' >< prod
  )
  {
    install_path_key = name - "SMB/Registry/HKLM/";
    install_path_key -= "/DisplayName";
    install_path_key += "\InstallLocation";
    install_path_key = str_replace(find:'/', replace:'\\',
                                   string:install_path_key);
    install_path = get_registry_value(handle:hklm, item:install_path_key);
    if (!isnull(install_path))
    {
      path = install_path;
      break; # installer enforces one install only
    }
  }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

close_registry(close:FALSE);

if(path[strlen(path)-1] == '\\')
  file = path + 'BTTray.exe';
ver = hotfix_get_fversion(path:file);

hotfix_check_fversion_end();

if (ver['error'] != HCF_OK)
{
  share = hotfix_path2share(path:file);
  if (ver['error'] == HCF_NOENT)
    audit(AUDIT_UNINST, appname);
  else if (ver['error'] == HCF_CONNECT)
    exit(1, "Error connecting to SMB service on remote host.");
  else if (ver['error'] == HCF_UNACCESSIBLE_SHARE)
    audit(AUDIT_SHARE_FAIL, share);
  else if (ver['error'] == HCF_NOAUTH)
    exit(1, "Error accessing '" + file + "'. Invalid credentials or share doesn't exist.");
  else if (ver['error'] == HCF_NOVER)
    audit(AUDIT_VER_FAIL, file);
  else
    exit(1, "Unknown error when attempting to access '" + file + "'.");
}

version = join(sep: '.', ver['value']);

set_kb_item(name:kb_base+'Path', value:path);
set_kb_item(name:kb_base+'Version', value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:lenovo:thinkpad_bluetooth_with_enhanced_data_rate_software");

if (report_verbosity > 0)
{
  report +=
    '\n  Path         : ' + path +
    '\n  Version      : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
