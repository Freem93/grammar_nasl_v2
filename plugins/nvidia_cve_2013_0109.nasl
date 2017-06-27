#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83521);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/20 14:21:42 $");

  script_cve_id("CVE-2013-0109", "CVE-2013-0110", "CVE-2013-0111");
  script_bugtraq_id(58459, 58460, 58461);
  script_osvdb_id(90947, 90948, 90949);
  script_xref(name:"CERT", value:"957036");
  script_xref(name:"EDB-ID", value:"30393");

  script_name(english:"NVIDIA Display Driver 174.x < 307.78 / 310.x < 311.00 Multiple Vulnerabilities");
  script_summary(english:"Checks Driver Version");

  script_set_attribute(attribute:"synopsis", value:
"A video display service on the remote Windows host is affected by
multiple privilege escalation vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA Display Driver service on the remote Windows
host is later than 174.00 but prior to 307.78, or later than 310.00
but prior to 311.00. It is therefore affected by the following
vulnerabilities :

  - An privilege escalation vulnerability exists due to not
    properly handling exceptions. A local attacker, using a
    crafted application, could exploit this to overwrite
    memory, allowing the execution of arbitrary code or
    causing a denial of service. (CVE-2013-0109)

  - A privilege escalation vulnerability exists in the
    Stereoscopic 3D Driver service due to an unquoted
    service search path. A local attacker, using a trojan
    horse program, could exploit this to execute arbitrary
    code in the root path. (CVE-2013-0110)

  - A privilege escalation vulnerability exists in the
    Update Service Daemon due to an unquoted service search
    path. A local attacker, using a trojan horse program,
    could exploit this to execute arbitrary code in the root
    path. (CVE-2013-0111)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/3288");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NVIDIA graphics drivers version 307.78 / 311.00 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Nvidia (nvsvc) Display Driver Service Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:display_driver");
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

  # 174 - 304 Branch (304.xx - 309.xx)
  if ( version =~ "^17[4-9]\." ||
       version =~ "^1[89][0-9]\." ||
       version =~ "^2[0-9][0-9]\." ||
       version =~ "^30[0-9]\."
     )
  {
    if (ver_compare(ver:version, fix:"307.78", strict:FALSE) == -1)
      fix = '307.78';
  }

  # 310 Branch (310.xx - 318.xx)
  if (version =~ "^31[0-8]\." && ver_compare(ver:version, fix:"311.00", strict:FALSE) == -1)
    fix = '311.00';

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
