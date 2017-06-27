#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62799);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"Kaspersky Password Manager Installed (credentialed check)");
  script_summary(english:"Checks registry/file system for KPM");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A password management application is installed on the remote Windows
host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Kaspersky Password Manager (KPM) was detected on the remote host.  KPM
provides automated username and password storage and can complete web
forms automatically."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/us/kaspersky-password-manager");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:kaspersky:kaspersky_password_manager");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

port = kb_smb_transport();
app = 'Kaspersky Password Manager';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Kaspersky Password Manager_is1";
path = get_registry_value(handle:hklm, item:key + "\InstallLocation");
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);
exe = path + "stpass.exe";
version_data = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (version_data['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, app);

if (version_data['error'] == HCF_NOVER)
  ver = UNKNOWN_VER;
else if (version_data['error'] == HCF_OK)
  ver = join(sep:'.', version_data['value']);
else
  audit(AUDIT_VER_FAIL, exe);

kb_base = "SMB/Kaspersky/PasswordManager/";
set_kb_item(name:kb_base+'Path', value:exe);
set_kb_item(name:kb_base+'Version', value:ver);


register_install(
  app_name:app,
  path:path,
  version:ver,
  cpe:"x-cpe:/a:kaspersky:kaspersky_password_manager");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + ver + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
