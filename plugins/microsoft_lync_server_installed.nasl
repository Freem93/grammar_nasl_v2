#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68879);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/11/11 02:55:08 $");

  script_name(english:"Microsoft Lync Installed");
  script_summary(english:"Checks the registry/FS for Lync.");

  script_set_attribute(attribute:"synopsis", value:
"A communication application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Microsoft Lync (previously known as Microsoft Office Communications)
is installed on the remote host. Microsoft Lync provides
communications services such as instant messaging, VoIP, and video
conferencing.");
  script_set_attribute(attribute:"see_also", value:"https://products.office.com/en-us/skype-for-business/online-meetings");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_basic");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_attendee");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:lync_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:live_meeting_console");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

appname = "Microsoft Lync";
get_kb_item_or_exit('SMB/Registry/Enumerated');
arch = get_kb_item_or_exit("SMB/ARCH");

installs = make_array();
# Lync components/services
rt_comm_keys = make_array(
  "92AC8981-AAD9-4391-8563-92E558EEF4C6", "Live Communications Server",
  "A593FD00-64F1-4288-A6F4-E699ED9DCA35", "Lync Server",
  "A766C25B-A1D1-4711-A726-AC3E7CA4AAB3", "Lync Core Components",
  "2A65AB9C-57AD-4EC6-BD4E-BD61A7C583B3", "Lync Web Components",
  "11CFB169-07EA-489D-BF8C-D8D29525720E", "Lync Response Group Service"
);

lync_vers = make_array();
# Live Communications Server 2005
lync_vers["2.0"]["prod"] = "Live Communications Server 2005";

# Live Communications Server 2007
lync_vers["3.0"]["prod"] = "Office Communications Server 2007";

# Lync Server 2010
lync_vers["4.0"]["prod"] = "2010";

# Lync Server 2013
lync_vers["5.0"]["prod"] = "2013";

# First check for server deployments
installs = make_array();
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Real-Time Communications\{A766C25B-A1D1-4711-A726-AC3E7CA4AAB3}";
names = make_list('InstallDir', 'Version');
values = get_values_from_key(handle:hklm, key:key, entries:names);

if (!empty_or_null(values))
{
  components = make_list();
  path = values["InstallDir"];
  display_ver = values["Version"];
  ver = split(display_ver, sep:'.', keep:FALSE);
  ver = ver[0] + "." + ver[1];

  # Determine the installed components
  key = "SOFTWARE\Microsoft\Real-Time Communications";
  subkeys = get_registry_subkeys(handle:hklm, key:key, wow:TRUE);
  foreach item (keys(subkeys))
  {
    foreach subkey (subkeys[item])
    {
      if (subkey !~ '^{[A-Z0-9\\-]+}$')
        continue;
      if (!empty_or_null(rt_comm_keys[subkey]))
        components = make_list(components, rt_comm_keys[subkey]);
    }
  }
  if (!empty_or_null(path) && !empty_or_null(display_ver))
  {
    installs["server"][ver]["path"] = path;
    installs["server"][ver]["version"] = display_ver;
    installs["server"][ver]["components"] = components;
  }
}

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!empty_or_null(list))
{
  foreach key (keys(list))
  {
    if ('Microsoft Office Live Meeting 2007' >< list[key])
    {
      key = str_replace(string:key, find:"/DisplayName", replace:"/InstallLocation");
      key = key - "SMB/Registry/HKLM/";
      key = str_replace(string:key, find:"/", replace:'\\');
      path = get_registry_value(handle:hklm, item:key);
      if (isnull(path) && arch == "x64")
      {
        key = str_replace(find:"SOFTWARE\Microsoft", replace:"SOFTWARE\Wow6432Node\Microsoft", key);
        path = get_registry_value(handle:hklm, item:key);
      }
      if (!empty_or_null(path))
        installs["live_meeting_2007"] = path;
    }
  }
}

# Now check for client installs
installs["client"]["paths"] = make_list();
regkeys = make_list(
  '\\Microsoft\\Communicator',
  '\\Microsoft\\AttendeeCommunicator'
);
foreach key (regkeys)
{
  path = get_registry_value(handle:hklm, item:"Software" + key + "\InstallationDirectory");
  if (isnull(path) && arch == "x64")
    path = get_registry_value(handle:hklm, item:"Software\Wow6432Node" + key + "\InstallationDirectory");
  if (!isnull(path))
  {
    installs["client"]["paths"] = make_list(installs["client"]["paths"], path);
    if ("Attendee" >< key)
      installs["client"][path] = "AttendeeCommunicator.exe";
    else
      installs["client"][path] = "Communicator.exe";
  }
}

# Lync Basic
subkeys = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Office", wow:TRUE);
if (!empty_or_null(subkeys))
{
  foreach item (keys(subkeys))
  {
    foreach subkey (subkeys[item])
    {
      if (subkey !~ '^[0-9\\.]+$') continue;
      ver = subkey;

      path = get_registry_value(handle:hklm, item:item + '\\' + ver + "\Lync\InstallationDirectory");
      if (!isnull(path)) installs["basic"][ver] = path;
    }
  }
}

# Lync / Skype for Business 2016 Client
path = get_registry_value(handle:hklm, item:"SOFTWARE\IM Providers\Lync\Icon");
if (isnull(path) && arch == "x64")
  path = get_registry_value(handle:hklm, item:"SOFTWARE\Wow6432Node\IM Providers\Lync\Icon");
if ("lync.ico" >< path)
{
  path = path - "lync.ico";
  installs["client"]["paths"] = make_list(installs["client"]["paths"], path);
  installs["client"][path] = "Lync.exe";
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

extra = make_array();
installed = FALSE;
# Lastly, look for User-level installs and check the binaries for other installs
userpaths = hotfix_get_user_dirs();
foreach userdir (userpaths)
{
  dll = hotfix_append_path(path:userdir, value:"Microsoft Lync Attendee\MeetingJoinAxAOC.DLL");
  fver = hotfix_get_fversion(path:dll);
  err = hotfix_handle_error(error_code:fver['error'], file:dll, appname:appname, exit_on_fail:FALSE);

  if (!empty_or_null(fver['value']))
  {
    mver = fver["value"];
    mver = mver[0] + "." + mver[1];

    extra["Product"] = "Microsoft Lync Attendee (User Level)";
    if (lync_vers[mver])
      extra["Product"] = extra["Product"] + " " + lync_vers[mver]["prod"];

    register_install(
      app_name:appname,
      path:hotfix_append_path(path:userdir, value:"Microsoft Lync Attendee"),
      version:join(fver["value"], sep:"."),
      extra:extra,
      cpe:"cpe:/a:microsoft:lync_attendee"
    );
    installed = TRUE;
  }
}

extra = make_array();
foreach ver (keys(installs["server"]))
{
  path = hotfix_append_path(path:installs["server"][ver]["path"], value:"Deployment\Deploy.exe");
  fver = hotfix_get_fversion(path:path);

  if (!empty_or_null(fver['value']))
  {
    mver = fver["value"];
    mver = mver[0] + "." + mver[1];

    extra["Product"] = "Microsoft Lync Server";
    if (lync_vers[mver])
      extra["Product"] = extra["Product"] + " " + lync_vers[mver]["prod"];

    register_install(
      app_name:appname,
      path:installs["server"][ver]["path"],
      version:join(fver["value"], sep:"."),
      extra:extra,
      cpe:"cpe:/a:microsoft:lync_server"
    );
    installed = TRUE;
  }
}

extra = make_array();
foreach path (installs["client"]["paths"])
{
  exe = hotfix_append_path(path:path, value:installs["client"][path]);
  fver = hotfix_get_fversion(path:exe);
  err = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);

  if (!empty_or_null(fver['value']))
  {
    mver = fver["value"];
    mver = mver[0] + "." + mver[1];
    if ('Attendee' >< path)
      extra["Product"] = "Microsoft Lync Attendee";
    else
      extra["Product"] = "Microsoft Lync";
    if (!empty_or_null(lync_vers[mver]))
    {
      extra["Product"] = extra["Product"] + " " + lync_vers[mver]["prod"];
    }

    register_install(
      app_name:appname,
      path:path,
      version:join(fver["value"], sep:"."),
      extra:extra,
      cpe:"cpe:/a:microsoft:lync"
    );
    installed = TRUE;
  }
}

extra = make_array();
if (!empty_or_null(installs["basic"]))
{
  foreach ver (keys(installs["basic"]))
  {
    path = installs["basic"][ver];
    exe = hotfix_append_path(path:path, value:"Lync.exe");
    fver = hotfix_get_fversion(path:exe);
    err = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);

    if (!empty_or_null(fver['value']))
    {
      extra["Product"] = "Microsoft Lync Basic";
      if (!empty_or_null(lync_vers[ver]))
        extra["Product"] = extra["Product"] + " " + lync_vers[ver]["prod"];

      register_install(
        app_name:appname,
        path:path,
        version:join(fver["value"], sep:"."),
        extra:extra,
        cpe:"cpe:/a:microsoft:lync_basic"
      );
      installed = TRUE;
    }
  }
}

extra = make_array();
if (!empty_or_null(installs["live_meeting_2007"]))
{
  path = installs["live_meeting_2007"];
  dll = hotfix_append_path(path:path, value:"pubutil.dll");
  fver = hotfix_get_fversion(path:dll);
  err = hotfix_handle_error(error_code:fver['error'], file:dll, appname:appname, exit_on_fail:FALSE);

  if (!empty_or_null(fver['value']))
  {
    register_install(
      app_name:appname,
      path:path,
      version:join(fver["value"], sep:"."),
      extra:make_array("Product", "Live Meeting 2007 Console"),
      cpe:"cpe:/a:microsoft:live_meeting_console"
    );
    installed = TRUE;
  }
}
hotfix_check_fversion_end();

if (!installed)
  audit(AUDIT_UNINST, 'Microsoft Lync Server');

report_installs(app_name:appname, port:kb_smb_transport());
