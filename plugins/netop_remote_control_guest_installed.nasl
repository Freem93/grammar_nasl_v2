#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58770);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/07 18:43:42 $");

  script_name(english:"Netop Remote Control Guest Detection");
  script_summary(english:"Checks for Netop Remote Control Guest install");

  script_set_attribute(attribute:"synopsis", value:"There is remote control client software installed on the remote host.");
  script_set_attribute(
    attribute:"description",
    value:
"Netop Remote Control Guest is installed on the remote Windows host.
It is client software that allows remote management of machines that
have Netop Remote Control Host installed."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.netop.com/products/administration/remote.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netop:remote_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

port = kb_smb_transport();
appname = 'Netop Remote Control Guest';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
subkeys = get_registry_subkeys(handle:hklm, key:key);

path = NULL;
ver_ui = NULL;

foreach subkey (subkeys)
{
  display_name_key = key + "\" + subkey + "\DisplayName";

  # double check we are looking at the right software
  display_name = get_registry_value(handle:hklm, item:display_name_key);

  # only one install is possible, installer exits out if already installed
  if (display_name =~ "Netop Remote Control Guest")
  {
    publisher_key = key + "\" + subkey + "\Publisher";
    publisher = get_registry_value(handle:hklm, item:publisher_key);
    # double check to make sure we have the right software
    if (publisher != "Netop Business Solutions A/S")
      continue;

    display_version_key = key + "\" + subkey + "\DisplayVersion";
    install_location_key = key + "\" + subkey + "\InstallLocation";

    ver_ui = get_registry_value(handle:hklm, item:display_version_key);
    if (isnull(ver_ui))
      exit(1, "Unable to obtain value for key : " + display_version_key + '\n');
    path = get_registry_value(handle:hklm, item:install_location_key);
    if (isnull(path))
      exit(1, "Unable to obtain value for key : " + install_location_key);

    break;
  }
}

RegCloseKey(handle:hklm);

if (path == NULL || ver_ui == NULL)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

RegCloseKey(handle:hklm);

version = NULL;

exe = path + "Guest\ngstw32.exe";
ver = hotfix_get_fversion(path:exe);
if(!isnull(ver['value']))
{
  str_ver = join(sep: '.', ver['value']);
  version = str_ver;
}

hotfix_check_fversion_end();

if(version != NULL)
{
  kb_base = "SMB/Netop_Remote_Control_Guest/";

  set_kb_item(name:kb_base + "Installed", value: TRUE);
  set_kb_item(name:kb_base + "Path", value: path);
  set_kb_item(name:kb_base + "Version", value: version);
  set_kb_item(name:kb_base + "Version_UI", value: ver_ui);

  register_install(
    app_name:appname,
    path:path,
    version:version,
    cpe:"cpe:/a:netop:remote_control");

  report =
    '\n Path    : ' + path +
    '\n Version : ' + ver_ui + ' (' + version + ')\n';

  if (report_verbosity > 0) security_note(port:port, extra:report);
  else security_note(port);

  exit(0);
}
else
  audit(AUDIT_UNINST, appname);
