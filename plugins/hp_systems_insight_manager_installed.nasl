#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59683);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/06 11:43:22 $");

  script_name(english:"HP Systems Insight Manager Detection (credentialed check)");
  script_summary(english:"Checks for HP Systems Insight Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is running a web application for remotely
managing systems.");
  script_set_attribute(attribute:"description", value:
"HP Systems Insight Manager, a web-based application for managing
remote systems, is installed on the remote Windows host.");

  script_set_attribute(attribute:"see_also", value:"http://h18000.www1.hp.com/products/servers/management/hpsim/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:systems_insight_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_ports(139, 445);
  script_require_keys("SMB/Registry/Enumerated");

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

app = 'HP Systems Insight Manager';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key  = "SOFTWARE\Hewlett-Packard\Systems Insight Manager\Settings\InstallPath";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

init_file = hotfix_append_path(path:path, value:"config\init.status");
share = hotfix_path2share(path:path);

file = hotfix_get_file_contents(init_file);
contents = file["data"];

hotfix_handle_error(
  error_code   : file["error"],
  file         : init_file,
  appname      : app,
  exit_on_fail : TRUE
);

version = NULL;

if (contents && 'MX_CONFIGURED_VERSION=' >< contents)
{
  chunk = contents - strstr(contents, 'MX_INIT_PERCENT_COMPLETE');
  version = strstr(chunk, 'MX_CONFIGURED_VERSION') - 'MX_CONFIGURED_VERSION=';
  version = chomp(version);
}
else audit(AUDIT_UNKNOWN_APP_VER, app);

if (isnull(version) || version !~ "^[A-Z]\.[0-9\.]+$") exit(1, "Failed to parse the version number from "+init_file+".");

# Parse installed hotfixes
hotfixes = make_list();
hotfixes_path = hotfix_append_path(path:path, value:"patch");
hotfixes_path = ereg_replace(string:hotfixes_path, pattern:"^\w:(.*)", replace:"\1");

hotfixes_list = list_dir(basedir:hotfixes_path, level:0, file_pat:"HOTFIX.*", share:share);
hotfix_check_fversion_end();

if (max_index(hotfixes_list) > 0)
  foreach hotfix (hotfixes_list)
  {
    match = eregmatch(pattern:"\\([A-Za-z0-9_]+)\.jar$", string:hotfix);
    if (match) hotfixes = make_list(hotfixes, match[1]);
  }

extra = make_array("Hotfixes", hotfixes);

register_install(
  app_name:app,
  path:    path,
  version: version,
  cpe:     "cpe:/a:hp:systems_insight_manager",
  extra:   extra
);

report_installs(port:port);
