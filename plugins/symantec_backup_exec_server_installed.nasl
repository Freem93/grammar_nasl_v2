#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55115);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/07/12 02:12:32 $");

  script_name(english:"Symantec Backup Exec Server / System Recovery Installed");
  script_summary(english:"Checks for Symantec Backup Exec Server");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a backup server installed on it.");
  script_set_attribute(attribute:"description", value:
"Symantec System Recovery, formerly Backup Exec Server, a data backup
and recovery application, is installed on the remote Windows host.");

  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/business/products/family.jsp?familyid=backupexec");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/system-recovery-server-edition");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:backupexec_system_recovery");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

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
key = "SOFTWARE\Symantec\Backup Exec For Windows\Backup Exec\Server\OriginalInstalledDBDeviceFile";
port = kb_smb_transport();
appname = 'Symantec Backup Exec';

path = NULL;
paths = make_array();

# First check for Symantec Backup Exec
path = get_registry_value(handle:hklm, item:key);
if (!isnull(path))
{
  path = path - strstr(path, '\\Data');
  paths[path] = 'SMB/Symantec Backup Exec Server/';
}

# Now check for Symantec System Recovery
key = "SOFTWARE\Symantec\Symantec System Recovery";
subkeys = get_registry_subkeys(handle:hklm, key:key);
foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + '\\InstallDir';
    path = get_registry_value(handle:hklm, item:entry);

    if (!isnull(path)) paths[path] = 'SMB/Symantec System Recovery/';
  }
}
RegCloseKey(handle:hklm);

if (max_index(keys(paths)) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

installs = make_array();
validatedinstall = FALSE;
foreach path (keys(paths))
{
  if ('Backup Exec Server' >< paths[path])
    exe = path + "\beserver.exe";
  else
    exe = path + "\Console\VProConsole.exe";
  ver = hotfix_get_fversion(path:exe);
  if (!isnull(ver['value']))
  {
    validatedinstall = TRUE;
    str_ver = join(sep:'.', ver['value']);
    installs[path] = str_ver;
  }
}
hotfix_check_fversion_end();

if (!validatedinstall)
  audit(AUDIT_UNINST, appname);

ssrinstall = FALSE;
report = '';
foreach path (keys(installs))
{
  if ('Backup Exec Server' >< paths[path])
  {
    set_kb_item(name:'SMB/Symantec_Backup_Exec_Server/version', value:installs[path]);
    set_kb_item(name:'SMB/Symantec_Backup_Exec_Server/path', value:path);

    register_install(
      app_name:appname,
      path:path,
      version:installs[path],
      cpe:"cpe:/a:symantec:veritas_backup_exec");
  }
  else
  {
    set_kb_item(name:paths[path]+'Installs/'+installs[path], value:path);
    register_install(
      app_name:appname,
      path:path,
      version:installs[path],
      cpe:"cpe:/a:symantec:backupexec_system_recovery");

    if (!ssrinstall)
    {
      ssrinstall = TRUE;
      set_kb_item(name:'SMB/Symantec System Recovery/Installed', value:TRUE);
    }
  }

  report +=
    '\n  Path    : ' + path +
    '\n  Version : ' + installs[path] + '\n';
}
if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
