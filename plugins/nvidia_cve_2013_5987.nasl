#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72483);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/24 02:15:10 $");

  script_cve_id("CVE-2013-5987");
  script_bugtraq_id(64525);
  script_osvdb_id(100517);
  script_xref(name:"IAVB", value:"2014-B-0011");

  script_name(english:"NVIDIA Graphics Driver Unspecified Privilege Escalation (Windows)");
  script_summary(english:"Checks Driver Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a driver installed that is affected by a local
privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a driver installed that is affected by an
unspecified, local privilege escalation vulnerability.  Using the
vulnerability, it may be possible for a local attacker to gain complete
control of the system."
  );
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/3377");
  script_set_attribute(attribute:"solution", value:"Upgrade to the appropriate video driver per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
if (isnull(kbs)) exit(0, 'No display drivers found.');

nvidia_found = FALSE;
foreach name (kbs)
  if ("NVIDIA" >< name) nvidia_found = TRUE;

if (!nvidia_found) exit(0, 'No NVIDIA display drivers found.');

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

  vuln = 0;

  # 310 Branch (310.xx - 312.xx)
  if (version =~ "^31[0-2]\." && ver_compare(ver:driver_date, fix:"2013.10.22", strict:FALSE) == -1)
    vuln++;

  # 319 Branch (319.xx - 321.xx)
  if (version =~ "^3(19|2[01])\." && ver_compare(ver:driver_date, fix:"2013.10.22", strict:FALSE) == -1)
    vuln++;

  # 325 Branch (325.xx - 327.xx)
  if (version =~ "^32[5-7]\." && ver_compare(ver:driver_date, fix:"2013.10.22", strict:FALSE) == -1)
    vuln++;

  # 331 Branch (331.xx to 333.xx)
  if (version =~ "^33[1-3]\." && ver_compare(ver:driver_date, fix:"2013.10.22", strict:FALSE) == -1)
    vuln++;

  # GeForce 6 and 7 series not affected
  # 304 Branch (304.xx - 309.xx)
  if (
    version =~ "^30[4-9]\." && 
    !isnull(gpu) && gpu !~ "GeForce [67][0-9]{3}($|[^0-9])" &&
    ver_compare(ver:driver_date, fix:"2013.10.22", strict:FALSE) == -1
  ) vuln++;

  if (vuln)
  {
    report += '\n  Device name       : ' + name +
              '\n  Driver version    : ' + version +
              '\n  Driver date       : ' + disp_driver_date + '\n';
  }
}

if (report != '')
{
  pre = '\n' + 'Based on the file date of the installed NVIDIA driver';
  if (vuln > 1) pre += 's, they ';
  else per += 'it ';
  pre += 'should' + '\n' + 'be updated and may be affected by the vulnerability.' + '\n\n';

  report = pre + report;

  if (report_verbosity > 0) security_hole(port:0, extra: report);
  else security_hole(0);
}
else exit(0, "No vulnerable NVIDIA display adapters were found.");
