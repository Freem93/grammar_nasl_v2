#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66316);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Adobe RoboHelp Installed");
  script_summary(english:"Checks if RH is installed");

  script_set_attribute(attribute:"synopsis", value:"An HTML authoring application is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Adobe RoboHelp, used to author and publish HTML content, is installed
on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/robohelp.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
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

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

keys = make_list(
  "SOFTWARE\Adobe\RoboHTML",
  "SOFTWARE\Adobe\RoboHelp"
);
paths = make_list(); # key - version, value - path

foreach key (keys)
{
  subkeys = get_registry_subkeys(handle:hklm, key:key);

  foreach version (subkeys)
  {
    if (version !~ "\d+\.") continue; # ignore keys that don't look like version numbers

    path = get_registry_value(handle:hklm, item:key + "\" + version + "\InstallFolder");
    if (!isnull(path))
      paths[version] = path;
  }
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Adobe RoboHelp');
}
else
{
  close_registry(close:FALSE);
}

report = NULL;
installs = 0;

foreach ver (keys(paths))
{
  path = paths[ver];
  if (path[strlen(path) - 1] != "\")
    path += "\";

  dll = path + "\redist\roboex32.dll";
  if (hotfix_file_exists(path:dll))
  {
    report +=
      '\n  Path : ' + path +
      '\n  Version : ' + ver + '\n';
    set_kb_item(name:'SMB/Adobe_RoboHelp/Version', value:ver);
    set_kb_item(name:'SMB/Adobe_RoboHelp/' + ver + '/Path', value:path);

    register_install(
      app_name:'Adobe RoboHelp',
      path:path,
      version:ver,
      cpe:"cpe:/a:adobe:robohelp");

    installs++;
  }
}

hotfix_check_fversion_end();

if (installs == 0)
  audit(AUDIT_UNINST, 'Adobe RoboHelp');

port = kb_smb_transport();

if (report_verbosity > 0)
{
  if (installs > 1) s = 's of Adobe RoboHelp were found ';
  else s = ' of Adobe RoboHelp was found ';
  report =
    '\n  The following install' + s + 'on the' +
    '\n  remote host :' +
    '\n' +
    report;
  security_note(port:port, extra:report);
}
else security_note(port);
