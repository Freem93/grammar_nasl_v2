#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65791);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/07/31 11:03:36 $");

  script_name(english:"Microsoft Windows Portable Devices");
  script_summary(english:"Checks for Historic Portable Device usage");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to get a list of portable devices that may have been
connected to the remote system in the past.");
  script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, this
plugin enumerates portable devices that have been connected to the
remote host in the past.");
  # http://msdn.microsoft.com/en-us/library/windows/hardware/gg463541.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af102b66");
  script_set_attribute(attribute:"solution", value:
"Make sure that use of the portable devices agrees with your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

deviceList = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows Portable Devices\Devices\\");
if (isnull(deviceList))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_REG_FAIL);
}

report = "";
foreach device (deviceList)
{
  wpd_device = get_reg_name_value_table(handle:hklm, key:"SOFTWARE\Microsoft\Windows Portable Devices\Devices\\"+device);
  if (isnull(wpd_device)) continue;

  report += '\n  Friendly name : ' + wpd_device["friendlyname"] +
            '\n  Device        : ' + device +
            '\n';
}

RegCloseKey(handle:hklm);
close_registry();

if (strlen(report) > 0)
{
  port = kb_smb_transport();
  if (report_verbosity > 0) security_note(port:port, extra:report);
  else security_note(port);
}
else exit(0, 'No portable devices found.');
