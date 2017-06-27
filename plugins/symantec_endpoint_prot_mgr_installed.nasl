#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59365);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/16 16:08:22 $");

  script_name(english:"Symantec Endpoint Protection Manager Installed (credentialed check)");
  script_summary(english:"Looks for SEP installation");

  script_set_attribute(attribute:"synopsis", value:
"An endpoint security management application is installed on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Symantec Endpoint Protection Manager, an endpoint security solution,
is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/endpoint-protection");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
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

appname = 'Symantec Endpoint Protection Manager';
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Symantec\Symantec Endpoint Protection\SEPM";
entries = make_list("TargetDir", "ProductType", "Version");
values = get_values_from_key(handle:hklm, entries:entries, key:key);
RegCloseKey(handle:hklm);

if (isnull(values))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else
{
  close_registry(close:FALSE);
}

path = values["TargetDir"];
edition = values["ProductType"];
ver = values["Version"];

# If we have no path, exit.
if (isnull(path)) audit(AUDIT_UNINST, appname);

# We now will only look at this file if running a paranoid check since
# it may report a low version number than the registry.
if (report_paranoia > 1)
{
  exe = path + "bin\ServiceUtil.exe";
  ver = hotfix_get_fversion(path:exe);
  hotfix_handle_error(
    error_code:ver['error'],
    file:exe,
    appname:appname,
    exit_on_fail:TRUE);

  ver = join(ver['value'], sep:'.');
}

hotfix_check_fversion_end();

# Vuln plugins expect a version so we should audit out if we have no
# version here.
if (isnull(ver)) audit(AUDIT_UNKNOWN_APP_VER, appname);

set_kb_item(name:'SMB/sep_manager/path', value:path);
set_kb_item(name:'SMB/sep_manager/ver', value:ver);

extra = make_array();

if (!isnull(edition))
{
  set_kb_item(name:'SMB/sep_manager/edition', value:edition);
  extra['Edition'] = edition;
}

# Register and report the install.
register_install(
  app_name:appname,
  path:path,
  version:ver,
  extra:extra,
  cpe:"cpe:/a:symantec:endpoint_protection_manager");

report_installs(port:kb_smb_transport());
