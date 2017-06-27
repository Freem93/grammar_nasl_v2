#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65674);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Novell Messenger Client Detection");
  script_summary(english:"Detects installs of Novell Messenger (formerly GroupWise Messenger) Client");

  script_set_attribute(attribute:"synopsis", value:"The remote host has an instant messaging client installed.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has Novell Messenger (formerly GroupWise Messenger)
client installed.  This is an instant messaging client based on Novell
eDirectory."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/documentation/novell_messenger22/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:messenger");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:groupwise_messenger");
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

appname = 'Novell Messenger Client';
kb_base = "SMB/Novell_Messenger_Client/";

port = kb_smb_transport();

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(1, "The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall' KB items are missing.");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = NULL;
exe = NULL;

foreach name (keys(list))
{
  prod = list[name];
  if (
    prod &&
    ('Novell Messenger' >< prod || 'GroupWise Messenger' >< prod)
  )
  {
    display_icon_key = name - "SMB/Registry/HKLM/";
    display_icon_key -= "/DisplayName";
    display_icon_key += "\DisplayIcon";
    display_icon_key = str_replace(find:'/', replace:'\\',
                                   string:display_icon_key);
    display_icon_path = get_registry_value(handle:hklm, item:display_icon_key);
    if (!isnull(display_icon_path))
    {
      item = eregmatch(string:display_icon_path,
                       pattern:"([a-zA-Z]:\\.*\\)([^\\]+)$");
      if (isnull(item)) exit(1, "Error parsing path from '" + display_icon_key + "' registry value.");

      # try and extract executable name from icon path string if possible
      if (display_icon_path =~ "\.(exe|EXE)[^\\]*$")
      {
        path = item[1];
        item = eregmatch(string: item[2], pattern: "(.*\.(exe|EXE)).*$");
        if (!isnull(item)) exe = item[1];
        else exe = "NMCL32.EXE";
      }
      else
      {
        path = item[1];
        exe = "NMCL32.EXE";
      }
      break; # only one install per machine possible
    }
  }
}

# for older installs on Windows 7 / Vista
if (isnull(path))
{
  path = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\NMCL32.EXE\Path");
  if (!isnull(path))
  {
    if (path[strlen(path)-1] != '\\')  path += '\\';
    exe = "NMCL32.EXE";
  }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

close_registry(close:FALSE);

file = path + exe;
ver = hotfix_get_fversion(path:file);

hotfix_check_fversion_end();

if (ver['error'] != HCF_OK)
{
  share = hotfix_path2share(path:file);
  if (ver['error'] == HCF_NOENT)
    audit(AUDIT_UNINST, appname);
  else if (ver['error'] == HCF_CONNECT)
    exit(1, "Error connecting to SMB service on remote host.");
  else if (ver['error'] == HCF_UNACCESSIBLE_SHARE)
    audit(AUDIT_SHARE_FAIL, share);
  else if (ver['error'] == HCF_NOAUTH)
    exit(1, "Error accessing '" + file + "'. Invalid credentials or share doesn't exist.");
  else if (ver['error'] == HCF_NOVER)
    audit(AUDIT_VER_FAIL, file);
  else
    exit(1, "Unknown error when attempting to access '" + file + "'.");
}

version = join(sep: '.', ver['value']);

set_kb_item(name:kb_base+'Path', value:path);
set_kb_item(name:kb_base+'Version', value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:novell:messenger");

if (report_verbosity > 0)
{
  report +=
    '\n  Path         : ' + path +
    '\n  Version      : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
