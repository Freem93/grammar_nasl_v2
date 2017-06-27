#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20844);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_name(english:"Vuze Installed");
  script_summary(english:"Determines if Vuze is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A peer-to-peer file sharing application is installed on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"Vuze (formerly Azureus), peer-to-peer file sharing software, is
installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.vuze.com/");
  script_set_attribute(attribute:"solution", value:
"Remove this software if it does not comply with your corporate
security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vuze:vuze");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:azureus_tracker:azureus_tracker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

appname = "Vuze";

key = "SOFTWARE\Azureus\";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
if (empty_or_null(path))
{
  key = hotfix_displayname_in_uninstall_key(pattern:"^(Vuze|Azureus)$");
  if (key)
  {
    path = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+ key +"/InstallLocation");
  }

  if (empty_or_null(path))
  {
    close_registry();
    audit(AUDIT_NOT_INST, appname);
  }
}

close_registry(close:FALSE);

exe  = hotfix_append_path(path:path, value:"Azureus.exe");
fver = hotfix_get_fversion(path:exe);

error = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);
if (error && fver['error'] != HCF_NOVER)
{
  hotfix_check_fversion_end();
  if (fver['error'] == HCF_NOENT)
    audit(AUDIT_UNINST, appname);
  exit(1, error);
}

ver  = NULL;
exe  = hotfix_append_path(path:path, value:"uninstall.exe");
fver = hotfix_get_fversion(path:exe);

error = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);
if (error && fver['error'] != HCF_NOVER)
{
  hotfix_check_fversion_end();
  exit(1, error);
}

if (!empty_or_null(fver['value']))
  ver = join(fver["value"], sep:".");

hotfix_check_fversion_end();

register_install(
  app_name: appname,
  path:     path,
  version:  ver,
  cpe:      "cpe:/a:vuze:vuze");

report_installs(app_name:appname, port:kb_smb_transport());
