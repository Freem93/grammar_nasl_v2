#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87412);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id(
    "CVE-2015-7865",
    "CVE-2015-7866",
    "CVE-2015-7869",
    "CVE-2015-8328"
  );
  script_bugtraq_id(83873);
  script_osvdb_id(
    130455,
    130456,
    130457,
    130643
  );
  script_xref(name:"EDB-ID", value:"38792");

  script_name(english:"NVIDIA Graphics Driver 340.x < 341.92 / 352.x < 354.35 / 358.x < 358.87 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA graphics driver installed on the remote
Windows host is 340.x prior to 341.92, 352.x prior to 354.35, or 358.x
prior to 358.87. It is, therefore, affected by multiple
vulnerabilities :

  - A privilege escalation vulnerability exists in the 
    Stereoscopic 3D Driver Service due to improper
    restriction of access to the 'stereosvrpipe' named pipe.
    An adjacent attacker can exploit this to execute
    arbitrary command line arguments, resulting in an
    escalation of privileges. (CVE-2015-7865)

  - A privilege escalation vulnerability exists due to an
    unquoted Windows search path issue in the Smart Maximize
    Helper (nvSmartMaxApp.exe). A local attacker can exploit
    this to escalate privileges. (CVE-2015-7866)

  - Multiple privilege escalation vulnerabilities exist in
    the NVAPI support layer due to multiple unspecified
    integer overflow conditions in the underlying kernel
    mode driver. A local attacker can exploit these issues
    to gain access to uninitialized or out-of-bounds memory,
    resulting in an escalation of privileges.
    (CVE-2015-7869, CVE-2015-8328)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3806");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3807");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3808");
  script_set_attribute(attribute:"solution", value:
"Upgrade to video driver version 341.92 / 354.35 / 358.87 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/11/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

report = '';

foreach kb (keys(kbs))
{
  name = kbs[kb];
  # only check NVIDIA drivers
  if ("NVIDIA" >!< name) continue;

  id = kb - kb_base - '/Name';

  version = get_kb_item_or_exit(kb_base + id + '/Version');
  driver_date = get_kb_item_or_exit(kb_base + id + '/DriverDate');

  disp_driver_date = driver_date;

  # convert to something we can pass to ver_compare (YYYY.MM.DD)
  driver_date = split(driver_date, sep:'/', keep:FALSE);
  driver_date = driver_date[2] + '.' + driver_date[0] + '.' + driver_date[1];

  fix = '';

  # 358 Branch
  if (version =~ "^358\." && ver_compare(ver:version, fix:"358.87", strict:FALSE) == -1)
    fix = '358.87';

  # 352 Branch
  if (version =~ "^35[2-4]\." && ver_compare(ver:version, fix:"354.35", strict:FALSE) == -1)
    fix = '354.35';

  # 340 Branch
  if (version =~ "^34[01]." && ver_compare(ver:version, fix:"341.92", strict:FALSE) == -1)
    fix = '341.92';

  if (fix != '')
  {
    report += '\n  Device name    : ' + name +
              '\n  Driver version : ' + version +
              '\n  Driver date    : ' + disp_driver_date + 
              '\n  Fixed version  : ' + fix + '\n';
  }
}
if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (report != '')
{
  if (report_verbosity > 0) security_hole(port:0, extra: report);
  else security_hole(0);
}
else exit(0, "No vulnerable NVIDIA display adapters were found.");
