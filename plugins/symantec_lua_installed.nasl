#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59192);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Symantec LiveUpdate Administrator Installed (credentialed check)");
  script_summary(english:"Checks registry/file system for LUA");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An update management application is installed on the remote Windows
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Symantec LiveUpdate Administrator (LUA) was detected on the remote
host.  LUA provides centralized management for multiple internal
LiveUpdate servers."
  );
  # http://www.symantec.com/connect/articles/installation-and-configuration-lua
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d69f033");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:liveupdate_administrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");
include("install_func.inc");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\Symantec\LiveUpdate Administrator";
names = make_list('InstallPath', 'Version');
values = get_values_from_key(handle:hklm, entries:names, key:key);
RegCloseKey(handle:hklm);

path = values['InstallPath'];
ver = values['Version'];

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'Symantec LUA');
}
else
{
  path = str_replace(string:path, find:'/', replace:"\");
}

close_registry(close:FALSE);
install_found = hotfix_file_exists(path:path + "luacert");
hotfix_check_fversion_end();

if (!install_found)
  audit(AUDIT_UNINST, 'Symantec LUA');

if (isnull(ver))
  ver = 'n/a';
else
  set_kb_item(name:'SMB/symantec_lua/ver', value:ver);

set_kb_item(name:'SMB/symantec_lua/path', value:path);

register_install(
  app_name:'Symantec LUA',
  path:path,
  version:ver,
  cpe:"cpe:/a:symantec:liveupdate_administrator");

port = kb_smb_transport();

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
