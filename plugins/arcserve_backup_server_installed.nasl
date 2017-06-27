#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62811);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:31 $");

  script_name(english:"CA ARCserve Backup Server Installed (credentialed check)");
  script_summary(english:"Checks for CA ARCserve Backup Server");

  script_set_attribute(attribute:"synopsis", value:"A backup application is installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"CA ARCserve Backup Server, a backup application, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.arcserve.com/us/Products/CA-ARCserve-Backup.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup");
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

registry_init();
port = kb_smb_transport();
appname = 'CA ARCserve Backup Server';

key_list = make_list("SOFTWARE\ComputerAssociates\CA ARCserve Backup\Base\Path\HOME",
                     "SOFTWARE\ComputerAssociates\BrightStor ARCserve Backup\Base\Path\HOME");

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
foreach key (key_list)
{
  path = get_registry_value(handle:hklm, item:key);
  if(!isnull(path)) break;
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

dll = path + "\asbackup.dll";
ver = hotfix_get_fversion(path:dll);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, appname);
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, dll);

version = join(sep:'.', ver['value']);

set_kb_item(name:'SMB/CA ARCserve Backup/Installed', value:TRUE);
set_kb_item(name:'SMB/'+appname+'/Path', value:path);
set_kb_item(name:'SMB/'+appname+'/Version', value:version);

register_install(
  app_name:appname,
  path:path,
  version:version,
  cpe:"cpe:/a:ca:arcserve_backup");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
