#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65701);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:34 $");

  script_name(english:"Viscosity VPN Client Detection");
  script_summary(english:"Detects Viscosity VPN Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a VPN client installed.");
  script_set_attribute(attribute:"description", value:"The remote host has the Viscosity VPN client installed.");
  script_set_attribute(attribute:"see_also", value:"http://www.sparklabs.com/viscosity/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:sparklabs:viscosity");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

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
appname = 'Viscosity';
kb_base = "SMB/Viscosity/";

display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (isnull(display_names)) audit(AUDIT_KB_MISSING, 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall');

in_registry = FALSE;
foreach key (display_names)
  if ('Viscosity' >< key) in_registry = TRUE;

if (!in_registry) audit(AUDIT_NOT_INST, appname);

install_num = 0;
path = NULL;

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
subkeys = get_registry_subkeys(handle:handle, key:key);

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if (display_name !~ "^Viscosity") continue;

  key -= '/DisplayName';
  key -= 'SMB/Registry/HKLM/';
  key = str_replace(string:key, find:"/", replace:'\\');

  publisher_key = key + "\Publisher";
  publisher = get_registry_value(handle:handle, item:publisher_key);
  if (publisher != "SparkLabs") continue;

  path_key = key + "\InstallLocation";
  path = get_registry_value(handle:handle, item:path_key);
  break;
}

RegCloseKey(handle:handle);
close_registry(close:FALSE);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

exe = path + "\Viscosity.exe";
ver = hotfix_get_fversion(path:exe);

hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, exe);

version = join(ver['value'], sep:'.');

set_kb_item(name: kb_base + "Path", value:path);
set_kb_item(name: kb_base + "Version", value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"x-cpe:/a:sparklabs:viscosity");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path    +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
