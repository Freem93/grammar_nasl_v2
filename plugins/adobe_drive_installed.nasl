#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62685);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:31 $");

  script_name(english:"Adobe Drive Installed");
  script_summary(english:"Checks registry & file system for Drive");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A digital asset management application is installed on the remote
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Adobe Drive is installed on the remote Windows host.  Drive provides
digital asset management that integrates with other applications in the
Adobe Creative Suite."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/adobedrive.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:adobe:drive");
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
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');
display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
path_keys = make_list();

foreach key (keys(display_names))
{
  display_name = display_names[key];
  if (display_name !~ '^Adobe Drive (CS)?[0-9.]+$') continue;

  key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  key = str_replace(string:key, find:'/', replace:"\");
  key += 'InstallLocation';
  path_keys = make_list(path_keys, key);
}

if (max_index(path_keys) == 0)
  audit(AUDIT_NOT_INST, 'Adobe Drive');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
paths = make_list();

foreach key (path_keys)
{
  path = get_registry_value(handle:hklm, item:key);
  if (!isnull(path))
    paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  # DisplayName was in the registry without a corresponding InstallLocation
  close_registry();
  exit(1, 'Unable to read install location from the registry.');
}
else
{
  close_registry(close:FALSE);
}

foreach path (paths)
{
  exe = path + "\ConnectUI\Adobe Drive.exe";
  version = NULL;

  ver =  hotfix_get_fversion(path:exe);
  if (ver['error'] == HCF_OK)
    version = join(ver['value'], sep:'.');
  else
    continue;

  set_kb_item(name:'SMB/Adobe_Drive/'+version+'/Path', value:path);

  register_install(
    app_name:'Adobe Drive',
    path:path,
    version:version,
    cpe:"x-cpe:/a:adobe:drive");
  installs++;

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
}

hotfix_check_fversion_end();

if (report)
{
  port = kb_smb_transport();
  set_kb_item(name:'SMB/Adobe_Drive/installed', value:TRUE);
  if (report_verbosity > 0)
  {
    if (installs > 1) s = 's of Adobe Drive were found ';
    else s = ' of Adobe Drive was found ';
    report =
      '\n  The following install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_UNINST, 'Adobe Drive');
