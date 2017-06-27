#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66420);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/10 22:03:56 $");

  script_name(english:"Microsoft Windows Essentials Installed");
  script_summary(english:"Checks registry & filesystem");

  script_set_attribute(attribute:"synopsis", value:"A desktop application suite is installed on the remote Windows host.");
  script_set_attribute(
    attribute:"description",
    value:
"Windows Essentials (formerly Windows Live Essentials and Windows Live
Installer) is installed on the remote host.  Windows Essentials is a
suite of applications for Windows."
  );
  script_set_attribute(attribute:"see_also", value:"http://essentials.live.com/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_essentials");
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
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
installs = make_array(); # key - uninstall key, value = version (NULL if it couldn't be determined)

# first check the Uninstall keys (stored in the KB) to see if looks like Essentials is installed
foreach key (keys(display_names))
{
  name = display_names[key];
  if (name != 'Windows Live Essentials') continue;

  version_key = key - 'DisplayName' + 'DisplayVersion';
  uninstall_key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  uninstall_key = str_replace(string:uninstall_key, find:'/', replace:"\");
  installs[uninstall_key] = get_kb_item(version_key);
}

if (max_index(keys(installs)) == 0)
  audit(AUDIT_NOT_INST, 'Windows Essentials');

# If it looks like it's installed, try to get the install path from the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

foreach key (keys(installs))
{
  path = get_registry_value(handle:hklm, item:key + "InstallLocation");
  if (!isnull(path))
    paths[path] = installs[key]; # key = path, value = version (NULL if it couldn't be determined)
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_UNINST, 'Windows Essentials');
}
else
{
  close_registry(close:FALSE);
}

report = NULL;

# verify that the installation actually exists. research indicates there will be
# at most one windows essentials installation per host
foreach path (keys(paths))
{
  ver = paths[path];
  if (path[strlen(path) - 1] != "\") # add a trailing slash if necessary
    path += "\";
  file = path + "Installer\wlarp.exe";

  if (hotfix_file_exists(path:file))
  {
    set_kb_item(name:'SMB/Windows_Essentials/Path', value:path);

    register_install(
      app_name:'Windows Essentials',
      path:path,
      version:ver,
      cpe:"cpe:/a:microsoft:windows_essentials");

    report += '\n  Path : ' + path;

    # haven't seen a situation where the version isn't available, but
    # this will be coded defensively anyway
    if (!isnull(ver))
    {
      set_kb_item(name:'SMB/Windows_Essentials/Version', value:ver);

      if (ver =~ "^16\.")
        report += '\n  Version : Windows Essentials 2012 (' + ver + ')';
      else if (ver =~ "^15\.")
        report += '\n  Version : Windows Live Essentials 2011 (' + ver + ')';
      else if (ver =~ "^14\.")
        report += '\n  Version : Windows Live Essentials 2009 (' + ver + ')';
      else
        report += '\n  Version : ' + ver;
    }
    else report += '\n  Version : unknown';

    report += '\n';

    break; # there is a max of one essentials install per system
  }
}

hotfix_check_fversion_end();

if (isnull(report))
  audit(AUDIT_UNINST, 'Windows Essentials');

port = kb_smb_transport();

if (report_verbosity > 0)
  security_note(port:port, extra:report);
else
  security_note(port);
