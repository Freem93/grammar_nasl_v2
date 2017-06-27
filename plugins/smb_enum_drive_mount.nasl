#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63080);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/11/28 21:50:18 $");

  script_name(english:"Microsoft Windows Mounted Devices");
  script_summary(english:"Checks for Historic mounted device usage"); 

  script_set_attribute(attribute:"synopsis", value:
"It is possible to get a list of mounted devices that may have been
connected to the remote system in the past.");
  script_set_attribute(attribute:"description", value:
"By connecting to the remote host with the supplied credentials, this
plugin enumerates mounted devices that have been connected to the remote
host in the past.");
  # http://msdn.microsoft.com/en-us/library/windows/hardware/ff567603(v=vs.85).aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3eee2c7c");
  script_set_attribute(attribute:"solution", value:
"Make sure that the mounted drives agree with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_reg_service_pack.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
drives = get_reg_name_value_table(handle:hklm, key:"SYSTEM\MountedDevices");
RegCloseKey(handle:hklm);
close_registry();

if (isnull(drives)) exit(0, "Unable to read the 'HKLM\SYSTEM\MountedDevices' registry key."); 

report = '\n';
foreach key (keys(drives))
{
  cval = "";
  data = drives[key];
  for (j=0; j<strlen(data); j++)
  {
    if (is_ascii_printable(char:data[j]))
      cval += data[j];
  }

  report += '  Name     : ' + key + '\n';
  report += '  Data     : ' + cval + '\n';
  report += '  Raw data : ' + hexstr(drives[key]) + '\n';
  report += '\n';
}

port = kb_smb_transport();
if (report_verbosity > 0) security_note(port:port, extra:report);
else security_note(port);
