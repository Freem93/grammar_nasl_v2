#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69427);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"RSA Authentication Agent Installed");
  script_summary(english:"Checks for RSA Authentication Agent");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has an authentication application installed.");
  script_set_attribute(attribute:"description", value:
"RSA Authentication Agent, an authentication application, is installed
on the remote Windows host.");
  #http://www.emc.com/security/rsa-securid/rsa-authentication-agents/windows.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?257f3e27");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:rsa:authentication_agent_for_windows");
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

app = 'RSA Authentication Agent';
port = kb_smb_transport;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\RSA\RSA Authentication Agent\CurrentVersion\InstallDir";
path = get_registry_value(handle:hklm, item:key);

key = "SOFTWARE\RSA\RSA Authentication Agent\CurrentVersion\ProductVersion";
version = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

if (isnull(version))
{
  close_registry();
  exit(1, 'Failed to get the version of ' + app + '\n');
}
close_registry(close:FALSE);

# Verify the application is still installed
exe = path + "\Disconnected Authentication\da_svc.exe";
ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT) audit(AUDIT_UNINST, app);
kb_base = 'SMB/' + app + '/';
set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:version);

register_install(
  app_name:app,
  path:path,
  version:version,
  cpe:"cpe:/a:rsa:authentication_agent_for_windows");

if (report_verbosity > 0)
{
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
