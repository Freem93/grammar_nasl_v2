#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
 script_id(25549);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/04/30 20:00:05 $");

 script_name(english:"Cisco VPN Client Version Detection");
 script_summary(english:"Detects the version of the Cisco VPN Client.");

 script_set_attribute(attribute:"synopsis", value:
"A VPN client is installed on the remote Windows host.");
 script_set_attribute(attribute:"description", value:
"Cisco VPN Client, used for secure connectivity, is installed on the
remote Windows host.");
 script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/c/en/us/products/security/vpn-client/index.html");
 script_set_attribute(attribute:"solution", value:"N/A");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/20");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:vpn_client");
 script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");
 script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
port = get_kb_item_or_exit("SMB/transport");

app_name = "Cisco VPN Client";

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

path = get_registry_value(handle:hklm, item:"SOFTWARE\Cisco Systems\VPN Client\InstallPath");

if(empty_or_null(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app_name);
}
close_registry(close:FALSE);

exe = hotfix_append_path(path:path, value:"vpngui.exe");

# Cisco sets file version to 0.0.0.0, for all versions. Will use product version.
version = hotfix_get_pversion(path:exe);

err = hotfix_handle_error(
      error_code  : version['error'],
      file        : exe,
      appname     : app_name,
      exit_on_fail: TRUE);

RegCloseKey(handle:hklm);

if (empty_or_null(version))
  version = UNKNOWN_VER;
  else
{
  version = join(version["value"], sep:".");
}

# Set KB items regardless of report verbosity
set_kb_item(name:"SMB/CiscoVPNClient/Path", value:path);
set_kb_item(name:"SMB/CiscoVPNClient/Version", value:version);

report = NULL;

if (report_verbosity > 0)
{
  report =
          '\n  Path    : ' + path +
          '\n  Version : ' + version + '\n';
}

security_note(port:port, extra:report);
