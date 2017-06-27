#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66271);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Google Apps Directory Sync Detection (Windows)");
  script_summary(english:"Checks for Google Apps Directory Sync on Windows");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains a LDAP synchronization tool.");
  script_set_attribute(attribute:"description", value:
"Google Apps Directory Sync, an application for syncing Google Apps user
accounts and your LDAP server, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://support.google.com/a/bin/answer.py?hl=en&answer=106368");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:google:apps_directory_sync");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");
appname = "Google Apps Directory Sync";
kb_base = "SMB/Google_Dir_Sync/";

registry_init();
list = get_kb_list_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

key = "SOFTWARE\ej-technologies\install4j\installations";
entry = "";
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
installKeys = get_reg_name_value_table(handle:handle, key:key);
foreach subkey (keys(installKeys))
{
  if (subkey =~ "^instdir")
  {
    entry = subkey;
    break;
  }
}
item = get_values_from_key(handle:handle, key:key, entries:make_list(entry));
value = item[entry];

if (isnull(value))
{
  uninstall_key = NULL;
  foreach name (keys(list))
  {
    prod = list[name];
    if ("Google Apps Directory Sync" >< prod)
    {
      installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:installstring);
      uninstall_key = key;
      break;
    }
  }
  if (isnull(uninstall_key)) audit(AUDIT_NOT_INST, appname);
  item = get_values_from_key(handle:handle, key:uninstall_key, entries:make_list('UninstallString'));
  value = item['UninstallString'];
  match = eregmatch(string:value, pattern:"([A-Za-z]:\\.*\\)[^\\]+\.exe");
  if (isnull(match))
  {
    RegCloseKey(handle:handle);
    close_registry();
    audit(AUDIT_NOT_INST, appname);
  }
  else
  {
    close_registry(close:FALSE);
    path = match[1];
    exe = path + 'checkforupdate.exe';
  }
}
else
{
  RegCloseKey(handle:handle);
  close_registry(close:FALSE);
  path = value;
  exe = path + "\checkforupdate.exe";
}

ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK) audit(AUDIT_VER_FAIL, appname);
ver2 = ver['value'];
version = ver2[0] + "." + ver2[1] + "." + ver2[2];

set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:version);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"x-cpe:/a:google:apps_directory_sync");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
   report =
     '\n  Path    : ' + path +
     '\n  Version : ' + version + '\n';
   security_note(port:port, extra:report);
}
else security_note(port);
