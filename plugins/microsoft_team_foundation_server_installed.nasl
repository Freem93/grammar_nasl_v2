#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62033);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/07 18:43:42 $");

  script_name(english:"Microsoft Visual Studio Team Foundation Server Detection (credentialed check)");
  script_summary(english:"Checks for Microsoft Visual Studio Team Foundation Server install");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a suite of tools for collaborative software
development."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running Microsoft Visual Studio Team Foundation
Server.  Team Foundation Server is a suite of tools for collaborative
software development."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_team_foundation_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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
appname = 'Microsoft Team Foundation Server';
kb_base = "SMB/Microsoft_Team_Foundation_Server/";

install_num = 0;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\TeamFoundationServer";
subkeys = get_registry_subkeys(handle:hklm, key:key);

paths = make_list();

foreach subkey (subkeys)
{
  if (subkey !~ "^[0-9.]+$") continue;

  entry = key + "\" + subkey + "\InstallPath";
  path = get_registry_value(handle:hklm, item:entry);

  if (isnull(path)) continue;
    paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
  close_registry(close:FALSE);

installs = make_array();

report = '';

foreach path (paths)
{
  # this DLL is always updated between versions
  exe = path + "\Tools\Microsoft.TeamFoundation.Framework.Server.dll";
  ver = hotfix_get_fversion(path:exe);

  version = '';
  if (isnull(ver['value'])) continue;

  version = join(ver['value'], sep:'.');

  set_kb_item(name: kb_base + install_num + "/Path", value: path);
  set_kb_item(name: kb_base + install_num + "/Version", value: version);

  register_install(
    app_name:appname,
    path:path,
    version:version,
    cpe:"cpe:/a:microsoft:visual_studio_team_foundation_server");

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';

  install_num++;
}

hotfix_check_fversion_end();

if (install_num == 0) audit(AUDIT_UNINST, appname);

set_kb_item(name:kb_base + 'NumInstalled', value:install_num);
set_kb_item(name:kb_base + 'Installed', value:TRUE);

if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
