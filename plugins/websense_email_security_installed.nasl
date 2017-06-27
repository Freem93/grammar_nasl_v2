#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69516);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:34 $");

  script_name(english:"Websense Email Security Installed");
  script_summary(english:"Checks for Websense Email Security");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has an email security application installed.");
  script_set_attribute(attribute:"description", value:
"Websense Email Security, an email security application, is installed
on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.websense.com/Content/websense-email-security-products.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/30");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:websense_email_security");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencie("smb_hotfixes.nasl");
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

port = kb_smb_transport();
appname = 'Websense Email Security';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Websense Email Security\Path";
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

exe = path + "\MessageAdmin.exe";
ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, exe);

version = join(ver['value'], sep:'.');
kb_base = 'SMB/Websense Email Security/';
set_kb_item(name:kb_base + 'Path', value:path);
set_kb_item(name:kb_base + 'Version', value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:websense:websense_email_security");

if (report_verbosity > 0)
{
  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
