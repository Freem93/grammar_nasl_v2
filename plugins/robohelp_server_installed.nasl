#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66315);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/26 20:00:05 $");

  script_name(english:"Adobe RoboHelp Server Installed");
  script_summary(english:"Checks if RHS is installed");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An application for managing web-based information is installed on the
remote Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Adobe RoboHelp Server, used to manage web help systems and knowledge
bases, is installed on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/robohelpserver.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
installs = make_array(); # key - uninstall key, value = version (NULL if it couldn't be determined)

foreach key (keys(display_names))
{
  name = display_names[key];
  if (name !~ "^Adobe RoboHelp Server \d+(\s+[x|X]\d+)?$") continue;

  version_key = key - 'DisplayName' + 'DisplayVersion';
  uninstall_key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  uninstall_key = str_replace(string:uninstall_key, find:'/', replace:"\");
  installs[uninstall_key] = get_kb_item(version_key);
}

if (max_index(keys(installs)) == 0)
  audit(AUDIT_NOT_INST, 'Adobe RoboHelp Server');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

foreach key (keys(installs))
{
  path = get_registry_value(handle:hklm, item:key + "DisplayIcon");
  if (!isnull(path))
    paths[path] = installs[key]; # key = path, value = version (NULL if it couldn't be determined)
}

RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_UNINST, 'Adobe RoboHelp Server');
}
else
{
  close_registry(close:FALSE);
}

report = NULL;
installs = 0;

# the documentation says you can only have one version of RoboHelp Server
# installed at once, but it's possible more than one are still in the registry
# after the directory has been manually deleted
foreach file (keys(paths))
{
  ver = paths[file];

  if (hotfix_file_exists(path:file))
  {
    webinf = strstr(file, 'WEB-INF');
    if (isnull(webinf)) # C:\program files\Adobe\Adobe RoboHelpServer 9\ARPRoboHelpServer.ico
    {
      dir ='';
      parts = split(file, sep:"\", keep:TRUE);
      for (i = 0; i < max_index(parts) - 1; i++)
        dir += parts[i];
    }
    else # C:\program files\Adobe\Adobe RoboHelpServer 8\WEB-INF\AMT\ConfigMgr.exe
      dir = file - webinf;

    report += '\n  Path : ' + dir;
    if (!isnull(ver))
    {
      report += '\n  Version : ' + ver;
      set_kb_item(name:'SMB/Adobe_RoboHelp_Server/Version', value:ver); # expect this to just be a major version e.g., 8 or 9
    }
    report += '\n';
    set_kb_item(name:'SMB/Adobe_RoboHelp_Server/Path', value:dir);

    register_install(
      app_name:'Adobe RoboHelp Server',
      path:dir,
      version:ver,
      cpe:"cpe:/a:adobe:robohelp_server");
  }
}

hotfix_check_fversion_end();

if (isnull(report))
  audit(AUDIT_UNINST, 'Adobe RoboHelp Server');

port = kb_smb_transport();

if (report_verbosity > 0)
  security_note(port:port, extra:report);
else
  security_note(port);
