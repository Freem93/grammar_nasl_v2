#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63417);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/10/27 15:14:57 $");

  script_bugtraq_id(57123);
  script_osvdb_id(88745);
  script_xref(name:"EDB-ID", value:"24207");

  script_name(english:"NVIDIA Display Driver Service Remote Stack Buffer Overflow (credentialed check)");
  script_summary(english:"Checks Driver Version");

  script_set_attribute(attribute:"synopsis", value:
"A video display service on the remote Windows host is affected by a
stack-based buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Display Driver Service on the remote Windows host is
affected by a remote stack-based buffer overflow. An authenticated,
remote attacker, by connecting to the nsvr named pipe and making a
specially crafted request, could exploit this to execute arbitrary
code as SYSTEM.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/dailydave/2013/q1/6");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55026");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55121");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55217");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55220");
  script_set_attribute(attribute:"see_also", value:"http://www.geforce.com/drivers/results/55599");
  script_set_attribute(attribute:"see_also", value:"http://www.nvidia.com/download/driverResults.aspx/56056");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA graphics drivers version 307.74 / 310.90 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nvidia (nvsvc) Display Driver Service Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:display_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

kb_base = 'WMI/DisplayDrivers/';

# double check in case optimization is disabled
kbs = get_kb_list(kb_base + '*/Name');
if (isnull(kbs)) exit(0, 'No display drivers were found.');

nvidia_found = FALSE;
foreach name (kbs)
  if ("NVIDIA" >< name) nvidia_found = TRUE;

if (!nvidia_found) exit(0, 'No NVIDIA display drivers were found.');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

report = '';

foreach kb (keys(kbs))
{
  name = kbs[kb];
  # only check NVIDIA drivers
  if ("NVIDIA" >!< name) continue;

  id = kb - '/Name';

  version = get_kb_item_or_exit(id + '/Version');
  driver_date = get_kb_item_or_exit(id + '/DriverDate');

  disp_driver_date = driver_date;

  fix = '';

  # 304 Branch (304.xx - 309.xx)
  if (version =~ "^30[4-9]\." && ver_compare(ver:version, fix:"307.74", strict:FALSE) == -1)
    fix = '307.74';

  # 310 Branch (310.xx - 318.xx)
  if (version =~ "^31[0-8]\." && ver_compare(ver:version, fix:"310.90", strict:FALSE) == -1)
    fix = '310.90';

  if (fix != '')
  {
    report += '\n  Device name    : ' + name +
              '\n  Driver version : ' + version +
              '\n  Driver date    : ' + disp_driver_date +
              '\n  Fixed version  : ' + fix + '\n';
  }
}

if (report != '')
{
  if (report_verbosity > 0) security_hole(port:0, extra: report);
  else security_hole(0);
}
else exit(0, "No vulnerable NVIDIA display adapters were found.");
