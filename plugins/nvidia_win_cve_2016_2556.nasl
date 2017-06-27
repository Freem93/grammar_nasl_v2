#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90119);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/10 14:39:21 $");

  script_cve_id(
    "CVE-2016-2556",
    "CVE-2016-2557",
    "CVE-2016-2558"
  );
  script_osvdb_id(
    135949,
    135950,
    135951
  );

  script_name(english:"NVIDIA Graphics Driver 340.x < 341.95 / 352.x < 354.74 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA graphics driver installed on the remote
Windows host is 340.x prior to 341.95 or 352.x prior to 354.74. It
is, therefore, affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists due to a
    kernel driver escape. A local attacker can exploit this
    to gain unauthorized access to restricted functionality,
    potentially allowing the execution of arbitrary code.
    (CVE-2016-2556)

  - An information disclosure vulnerability exists due to an
    out-of-bounds read error. A local attacker can exploit
    this to read arbitrary information from memory.
    (CVE-2016-2557)

  - An unspecified untrusted pointer flaw exists that allows
    a local attacker to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-2558)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4059");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4060");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4061");
  # http://us.download.nvidia.com/Windows/341.95/341.95-win8-win7-winvista-desktop-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cb06842");
  # http://drivers.softpedia.com/get/GRAPHICS-BOARD/NVIDIA/NVIDIA-GeForce-Graphics-Driver-34195-for-Windows-10-64-bit.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?88e2ba18");
  script_set_attribute(attribute:"see_also", value:"http://www.get-top-news.com/news-11914735.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to video driver version 341.95 / 354.74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/03/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/23");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

kb_base = 'WMI/DisplayDrivers/';

# double check in case optimization is disabled
kbs = get_kb_list(kb_base + '*/Name');
if (isnull(kbs)) exit(0, 'No display drivers were found.');

nvidia_found = FALSE;
report = '';

foreach kb (keys(kbs))
{
  name = kbs[kb];
  # only check NVIDIA drivers
  if ("NVIDIA" >!< name) continue;
  else
    nvidia_found = TRUE;

  id = kb - kb_base - '/Name';

  version = get_kb_item_or_exit(kb_base + id + '/Version');
  driver_date = get_kb_item_or_exit(kb_base + id + '/DriverDate');

  disp_driver_date = driver_date;

  # convert to something we can pass to ver_compare (YYYY.MM.DD)
  driver_date = split(driver_date, sep:'/', keep:FALSE);
  driver_date = driver_date[2] + '.' + driver_date[0] + '.' + driver_date[1];

  fix = '';

  # 340 Branch
  if (version =~ "^34[01]." && ver_compare(ver:version, fix:"341.95", strict:FALSE) == -1)
    fix = '341.95';

  # 352 Branch                                                        
  if (version =~ "^35[2-4]\." && ver_compare(ver:version, fix:"354.74", strict:FALSE) == -1)
    fix = '354.74';

  if (fix)
  {
    report += '\n  Device name    : ' + name +
              '\n  Driver version : ' + version +
              '\n  Driver date    : ' + disp_driver_date +
              '\n  Fixed version  : ' + fix + '\n';
  }
}

if (!nvidia_found) exit(0, 'No NVIDIA display drivers were found.');

if (report)
{
  security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
}
else exit(0, "No vulnerable NVIDIA display adapters were found.");
