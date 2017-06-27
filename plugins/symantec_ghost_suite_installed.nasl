#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62715);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/07/12 02:12:34 $");

  script_name(english:"Symantec Ghost Solution Suite Installed");
  script_summary(english:"Checks for Symantec Ghost Solution Suite");

  script_set_attribute(attribute:"synopsis", value:
"A system management and computer imaging application is installed on
the remote host.");
  script_set_attribute(attribute:"description", value:
"Symantec Solution Ghost Suite, a system management and computer imaging
application, is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://www.symantec.com/ghost-solution-suite");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:ghost_solutions_suite");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

port = kb_smb_transport();
app = 'Symantec Ghost Solution Suite';

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Symantec\Symantec Ghost\InstallDirectory\dbeng";
path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}
close_registry(close:FALSE);

path = ereg_replace(pattern:'^([A-Za-z]:\\\\.*)\\\\bin', string:path, replace:"\1");
exe = path + "\Ghostexp.exe";

ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST,'Symantec Ghost Solution Suite');
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, exe);

build = join(ver['value'], sep:'.');
kb_base = 'SMB/'+app+'/';
set_kb_item(name:kb_base+'Path', value:path);
set_kb_item(name:kb_base+'Build', value:build);

register_install(
  app_name:app,
  path:path,
  version:build,
  cpe:"cpe:/a:symantec:ghost_solutions_suite");

if (report_verbosity > 0)
{
  report +=
    '\n  Path  : ' + path +
    '\n  Build : ' + build + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
