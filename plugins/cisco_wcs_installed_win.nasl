#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69131);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/04/08 14:04:19 $");

  script_name(english:"Cisco Wireless Control System Installed (Windows)");
  script_summary(english:"Looks for WCS files");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A wireless management application is installed on the remote Windows
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Cisco Wireless Control System (WCS) is installed on the remote host.
WCS is used as the management component for Cisco Unified Wireless
Network."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps6305/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:wireless_control_system_software");
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

display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
uninstall_keys = make_list();

# first check the Uninstall keys (stored in the KB) to see if looks like WCS is installed
foreach key (keys(display_names))
{
  name = display_names[key];
  if (name !~ 'Cisco Wireless Control System') continue;

  uninstall_key = key - 'SMB/Registry/HKLM/' - 'DisplayName';
  uninstall_key = str_replace(string:uninstall_key, find:'/', replace:"\");
  uninstall_keys = make_list(uninstall_keys, uninstall_key);
}

if (max_index(uninstall_keys) == 0)
  audit(AUDIT_NOT_INST, 'Cisco WCS');

# If it looks like it's installed, try to get the path and version from the registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

paths = make_list();
foreach key (uninstall_keys)
{
  path = get_registry_value(handle:hklm, item:key + "InstallLocation");
  if (!isnull(path))
    paths = make_list(paths, path);
}
RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_UNINST, 'Cisco WCS');
}

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

foreach path(paths)
{
  share = hotfix_path2share(path:path);
  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  if (path[strlen(path) - 1] != "\") # add a trailing slash if necessary
    path += "\";
  props_file = substr(path, 2) + "webnms\classes\com\cisco\common\ha\config\ha.properties"; # strip out the leading drive name
  fh = CreateFile(
    file:props_file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (!isnull(fh))
  {
    properties = NULL;
    length = GetFileSize(handle:fh);
    if (length > 1024) length = 1024;  # sanity check - max size of 1k (it's a few hundred bytes in WCS 7.0.164.0)
    properties = ReadFile(handle:fh, offset:0, length:length);
    CloseFile(handle:fh);
  }

  match = eregmatch(string:properties, pattern:"version=([\d.]+)");
  if (isnull(match)) continue;

  version = match[1];
  set_kb_item(name:'SMB/cisco_wcs/version', value:version);
  set_kb_item(name:'SMB/cisco_wcs/' + version + '/path', value:path);
  register_install(
    app_name:'Cisco WCS',
    path:path,
    version:version,
    cpe:"cpe:/a:cisco:wireless_control_system_software");
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
}

NetUseDel();

if (isnull(report))
  audit(AUDIT_UNINST, 'Cisco WCS');

if (report_verbosity > 0)
  security_note(port:port, extra:report);
else
  security_note(port);

