#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69475);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"FileZilla Client Installed");
  script_summary(english:"Checks if the FileZilla Client is installed");

  script_set_attribute(attribute:"synopsis", value:"An open source FTP client is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"FileZilla, an open source FTP/SFTP client, is installed on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"https://filezilla-project.org/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:filezilla:filezilla");
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

paths = make_list();
paths_index = 0;
kb_base = "SMB/filezilla/";
appname = "FileZilla Client";

registry_init();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

values = get_registry_values(handle:hklm, items:make_list(
  # version 3.x stores it here
  "SOFTWARE\FileZilla Client\",
  # version 2.x stores it here
  "SOFTWARE\FileZilla\Install_Dir"
));

if (!isnull(values["SOFTWARE\FileZilla Client\"]))
  paths[paths_index++] = values["SOFTWARE\FileZilla Client\"];

if (!isnull(values["SOFTWARE\FileZilla\Install_Dir"]))
  paths[paths_index++] = values["SOFTWARE\FileZilla\Install_Dir"];

RegCloseKey(handle:hklm);

hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hku, key:'');
foreach key (subkeys)
{
  hku_path = get_registry_value(handle:hku, item:key + "\SOFTWARE\FileZilla Client\");

  if(!isnull(hku_path)) # add a path to check
    paths[paths_index++] = hku_path;
}
RegCloseKey(handle:hku);

if (paths_index == 0)
{
  # no paths found in the registry
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

versions = make_array();

foreach path (paths)
{
  filePath = path + "\FileZilla.exe";

  if (isnull(versions[filePath]))
  {
    # if we don't already have this file's version
    ver = hotfix_get_fversion(path:filePath);
    hotfix_check_fversion_end();
    if (ver['error'] == HCF_OK)
      versions[filePath] = join(ver['value'], sep:'.');
  }
}

# If any installs were found, mark it as installed in the KB and issue a report.
if (max_index(keys(versions)) > 0)
{
  set_kb_item(name:kb_base + "Installed", value:TRUE);

  info = "";
  installs = 0;
  foreach path (keys(versions))
  {
    version = versions[path];

    # At least one version of FileZilla ends with a letter, which
    # ver_compare() can't handle.
    version_number = 0;
    matches = eregmatch(string:version, pattern:"^([0-9.]+)");
    if (!isnull(matches))
      version_number = matches[1];

    set_kb_item(name:kb_base + "install/" + installs + "/Path", value:path);
    set_kb_item(name:kb_base + "install/" + installs + "/Version", value:version);
    set_kb_item(name:kb_base + "install/" + installs + "/VersionNumber", value:version_number);
    register_install(
      app_name:appname,
      path:path,
      version:version,
      cpe:"cpe:/a:filezilla:filezilla");

    info += '\n  Path    : ' + path;
    info += '\n  Installed Version : ' + version + '\n';

    installs++;
  }
  set_kb_item(name:kb_base + "installs", value:installs);

  if (report_verbosity > 0)
  {
    if (installs > 1) s = "s of FileZilla Client are";
    else s = " of FileZilla Client is";

    report =
      '\nThe following instance' + s +
      ' installed on the remote \nhost :\n' +
      info;

    port = kb_smb_transport();
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_UNINST, appname);

