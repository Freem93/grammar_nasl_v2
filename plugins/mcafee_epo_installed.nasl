#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67119);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"McAfee ePolicy Orchestrator Installed (credentialed check)");
  script_summary(english:"Checks registry/fs for epo");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A security management application is installed on the remote Windows
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"McAfee ePolicy Orchestrator, a centralized security management
application, is installed on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.mcafee.com/us/products/epolicy-orchestrator.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
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
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
installs = make_array(); # key - uninstall key, value = version (NULL if it couldn't be determined)

# first check the Uninstall keys (stored in the KB) to see if looks like ePO is installed
foreach key (keys(display_names))
{
  name = display_names[key];

  # 3.5 - "McAfee ePolicy Orchestrator 3.5.0"
  # 5.0 - "McAfee ePolicy Orchestrator"
  match = eregmatch(string:name, pattern:"^McAfee ePolicy Orchestrator( ([\d.]+))?$");
  if (isnull(match)) continue;

  uninstall_key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  uninstall_key = str_replace(string:uninstall_key, find:'/', replace:"\");

  # keep track of the version if it's in the display name.
  # the version is used to name the only subdir of the installation directory
  # for older versions of ePO
  installs[uninstall_key] = match[2];
}

if (max_index(keys(installs)) == 0)
  audit(AUDIT_NOT_INST, 'McAfee ePO');

# If it looks like it's installed, try to get the install path from the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_list();

foreach key (keys(installs))
{
  path = get_registry_value(handle:hklm, item:key + "InstallLocation"); # 4.6.5, 5.0
  if (isnull(path))
  {
    path = get_registry_value(handle:hklm, item:key + "ProductFolder"); # 3.5
    prod_ver = installs[key];
    if (!isnull(path) && !isnull(prod_ver))
      path = strcat(path, "\", prod_ver);
  }

  if (!isnull(path))
    paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);

if (keys(paths) == 0)
{
  close_registry();
  audit(AUDIT_UNINST, 'McAfee ePO');
}
else
{
  close_registry(close:FALSE);
}

report = NULL;

# verify that the installation actually exists. research indicates there will be
# at most one epo installation per host
foreach path (list_uniq(paths))
{
  ver = paths[path];
  if (path[strlen(path) - 1] != "\") # add a trailing slash if necessary
    path += "\";
  exe = path + "srvmon.exe";
  ver = hotfix_get_fversion(path:exe);
  status = ver['error'];
  ver = join(ver['value'], sep:'.');;

  if (status != HCF_OK || isnull(ver)) continue;

  set_kb_item(name:'SMB/mcafee_epo/Path', value:path);
  set_kb_item(name:'SMB/mcafee_epo/ver', value:ver);

  register_install(
    app_name:'McAfee ePO',
    path:path,
    version:ver,
    cpe:"cpe:/a:mcafee:epolicy_orchestrator");

  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver + '\n';
}

hotfix_check_fversion_end();

if (isnull(report))
  audit(AUDIT_UNINST, 'McAfee ePO');

port = kb_smb_transport();

if (report_verbosity > 0)
  security_note(port:port, extra:report);
else
  security_note(port);
