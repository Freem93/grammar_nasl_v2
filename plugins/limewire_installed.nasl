#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11427);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/03 21:15:46 $");

  script_name(english:"LimeWire Installed");
  script_summary(english:"Determines if LimeWire is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A peer-to-peer file sharing application is installed on the remote
Windows host.");
  script_set_attribute(attribute:"description", value:
"LimeWire, peer-to-peer file sharing software, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/LimeWire");
  script_set_attribute(attribute:"solution", value:
"Remove this software if it does not comply with your corporate
security policy.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:limewire:limewire");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

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

appname = "LimeWire";
key     = "SOFTWARE\LimeWire\InstallDir";

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (empty_or_null(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

exe  = hotfix_append_path(path:path, value:"LimeWire.exe");
fver = hotfix_get_fversion(path:exe);

error = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);
if (error && fver['error'] != HCF_NOVER)
{
  hotfix_check_fversion_end();
  exit(1, error);
}

ver = NULL;
exe = hotfix_append_path(path:path, value:"uninstall.exe"); 
fver = hotfix_get_fversion(path:exe);

error = hotfix_handle_error(error_code:fver['error'], file:exe, appname:appname, exit_on_fail:FALSE);
if (error && fver['error'] != HCF_NOVER)
{
  hotfix_check_fversion_end();
  exit(1, error);
}

if (!empty_or_null(fver['value']))
  ver = join(fver["value"], sep:".");
else
{
  display_name =
    get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/"+appname+"/DisplayName");
  match = eregmatch(string:display_name, pattern:"^LimeWire ([0-9.]+)$");
  if (!isnull(match[1]))
    ver = match[1];
}

hotfix_check_fversion_end();

register_install(
  app_name: appname,
  path:     path,
  version:  ver,
  cpe:      "cpe:/a:limewire:limewire");

report_installs(app_name:appname, port:kb_smb_transport());
