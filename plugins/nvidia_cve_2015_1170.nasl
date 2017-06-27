#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82528);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2015-1170");
  script_bugtraq_id(73442);
  script_osvdb_id(118959);
  script_xref(name:"IAVB", value:"2015-B-0045");

  script_name(english:"NVIDIA Graphics Driver Local Privilege Escalation");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privileges escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a driver installed this is affected by a
privilege escalation vulnerability due to a failure to properly
validate local client impersonation levels when performing a kernel
administrator check. A local attacker can exploit this issue, via 
unspecified API calls, to gain administrator privileges.");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/3634");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate video driver version per the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/02/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/02");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

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

  gpu = get_kb_item_or_exit(kb_base + id + '/Processor');

  fix = '';

  # 304 Branch (304.xx - 309.xx)
  if (version =~ "^30[4-9]\." && ver_compare(ver:version, fix:"309.08", strict:FALSE) == -1)
    fix = '309.08';

  # 340 Branch (340.xx - 341.xx)
  if (version =~ "^34[01]\." && ver_compare(ver:version, fix:"341.44", strict:FALSE) == -1)
    fix = '341.44';

  # 343 Branch (343.xx - 345.xx)
  if (version =~ "^34[345]\." && ver_compare(ver:version, fix:"345.20", strict:FALSE) == -1)
    fix = '345.20';

  # 346 Branch (346.xx - 347.xx)
  if (version =~ "^34[67]\." && ver_compare(ver:version, fix:"347.52", strict:FALSE) == -1)
    fix = '347.52';

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
