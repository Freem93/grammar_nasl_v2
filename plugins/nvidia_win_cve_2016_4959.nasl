#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93912);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id(
    "CVE-2016-3161",
    "CVE-2016-4959",
    "CVE-2016-4960",
    "CVE-2016-4961",
    "CVE-2016-5025",
    "CVE-2016-5852"
  );
  script_osvdb_id(
    143299,
    143300,
    143301,
    143302,
    143303,
    143304
  );

  script_name(english:"NVIDIA Graphics Driver 340.x < 341.96 / 352.x < 354.99 / 361.x < 362.77 / 367.x < 368.39 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA graphics driver installed on the remote
Windows host is 340.x prior to 341.96, 352.x prior to 354.99, 361.x
prior to 362.77, or 367.x prior to 368.39. It is, therefore, affected 
by multiple vulnerabilities :

  - A privilege escalation vulnerability exists in GFE
    GameStream due to an unquoted search path. A local
    attacker can exploit this, via a malicious executable in
    the root path, to elevate privileges. (CVE-2016-3161)

  - A denial of service vulnerability exists due to a NULL
    pointer dereference flaw. An unauthenticated, remote
    attacker can exploit this to cause a crash.
    (CVE-2016-4959)

  - A privilege escalation vulnerability exists in the
    NVStreamKMS.sys driver due to improper sanitization of
    user-supplied data passed via API entry points. A local
    attacker can exploit this to gain elevated privileges.
    (CVE-2016-4960)

  - A denial of service vulnerability exists in the
    NVStreamKMS.sys driver due to improper handling of
    parameters. An unauthenticated, remote attacker can
    exploit this to cause a crash. (CVE-2016-4961)

  - A denial of service vulnerability exists in the NVAPI
    support layer due to improper sanitization of
    parameters. An unauthenticated, remote attacker can
    exploit this to cause a crash. (CVE-2016-5025)

  - A privilege escalation vulnerability exists in the
    NVTray plugin due to an unquoted search path. A local
    attacker can exploit this, via a malicious executable in
    the root path, to elevate privileges. (CVE-2016-5852)

Note that CVE-2016-3161, CVE-2016-4960, CVE-2016-4961, and
CVE-2016-5852 only affect systems which also have GeForce Experience
software installed.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4213");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 341.96 / 354.99 / 362.77
/ 368.39 or later. Alternatively, for CVE-2016-4959, apply the
mitigation referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date",value:"2016/08/11");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");

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

  # 367 Branch
  if (version =~ "^36[78]\." && ver_compare(ver:version, fix:"368.39", strict:FALSE) == -1)
    fix = '368.39';
  
  # 361 Branch
  if (version =~ "^36[12]\." && ver_compare(ver:version, fix:"362.77", strict:FALSE) == -1)
    fix = '362.77';
  
  # 352 Branch
  if (version =~ "^35[2-4]\." && ver_compare(ver:version, fix:"354.99", strict:FALSE) == -1)
    fix = '354.99';

  # 340 Branch
  if (version =~ "^34[01]\." && ver_compare(ver:version, fix:"341.96", strict:FALSE) == -1)
    fix = '341.96';

  if (fix != '')
  {
    order = make_list('Device name','Driver version','Driver date','Fixed version');
    report = make_array(
      order[0],name,
      order[1],version,
      order[2],disp_driver_date,
      order[3],fix
      );
    report = report_items_str(report_items:report, ordered_fields:order);
  }
}
if (report != '')
{
  security_report_v4(severity:SECURITY_HOLE, port:0, extra: report);
}
else exit(0, "No vulnerable NVIDIA display adapters were found.");
