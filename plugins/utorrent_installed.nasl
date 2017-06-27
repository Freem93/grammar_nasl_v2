#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24341);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/03 21:15:46 $");

  script_name(english:"uTorrent Installed");
  script_summary(english:"Determines if uTorrent is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A peer-to-peer file sharing application installed on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"uTorrent, peer-to-peer file sharing software, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.utorrent.com/intl/en/");
  script_set_attribute(attribute:"solution", value:
"Remove this software if it does not comply with your corporate
security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:utorrent:utorrent");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

appname = "uTorrent";
paths = make_list();
errors = make_list();

keys = make_list(
  "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\uTorrent\InstallLocation",
  "SOFTWARE\Classes\uTorrent\shell\open\command\"
);

foreach key (keys)
{
  path = get_registry_value(handle:hklm, item:key);
  if (empty_or_null(path)) continue;

  if ("\command\" >< key)
  {
    path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:path);
    path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:path);
  }

  paths = make_list(paths, path);
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

foreach path (list_uniq(paths))
{
  ver  = NULL;
  exe  = hotfix_append_path(path:path, value:"uTorrent.exe");

  fver = hotfix_get_fversion(path:exe);

  error = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);
  if (error && fver['error'] != HCF_NOVER)
  {
    errors = make_list(errors, error);
    continue;
  }

  if (!empty_or_null(fver['value']))
    ver = join(fver["value"], sep:".");
  else
  {
    display_name =
      get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+appname+"/DisplayName");
    match = eregmatch(string:display_name, pattern:"^uTorrent ([0-9.]+)$");
    if (!isnull(match[1]))
      ver = match[1];
  }

  register_install(
    app_name: appname,
    path:     path,
    version:  ver,
    cpe:      "cpe:/a:utorrent:utorrent");
}

# Newer versions install in users' APPDATA directory
userpaths = hotfix_get_user_dirs();
foreach userpath (userpaths)
{
  ver  = NULL;
  path = ereg_replace(string:userpath, pattern:"(.*)\\Local$", replace:"\1\Roaming\" + appname);
  exe  = hotfix_append_path(path:path, value:"uTorrent.exe");

  if (!hotfix_file_exists(path:exe)) continue;

  fver = hotfix_get_fversion(path:exe);
  error = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);
  if (error && fver['error'] != HCF_NOVER)
  {
    errors = make_list(errors, error);
    continue;
  }

  if (!empty_or_null(fver['value']))
    ver = join(fver["value"], sep:".");

  register_install(
    app_name: appname,
    path:     path,
    version:  ver,
    cpe:      "cpe:/a:utorrent:utorrent");
}

hotfix_check_fversion_end();

if (get_install_count(app_name:appname) <= 0)
{
  if ((max_index(errors)) == 1)
    exit(1, 'The following error has occurred :\n' + errors[0]);
  else if ((max_index(errors)) > 1)
    exit(1, 'The following errors have occurred :\n' + join(errors, sep:'\n'));
  else
    audit(AUDIT_NOT_INST, appname);
}

report_installs(app_name:appname, port:kb_smb_transport());
