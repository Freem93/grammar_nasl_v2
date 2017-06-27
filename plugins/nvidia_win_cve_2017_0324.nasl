#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97386);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/19 14:17:02 $");

  script_cve_id(
    "CVE-2017-0308",
    "CVE-2017-0309",
    "CVE-2017-0310",
    "CVE-2017-0311",
    "CVE-2017-0312",
    "CVE-2017-0313",
    "CVE-2017-0314",
    "CVE-2017-0315",
    "CVE-2017-0317",
    "CVE-2017-0319",
    "CVE-2017-0320",
    "CVE-2017-0321",
    "CVE-2017-0322",
    "CVE-2017-0323",
    "CVE-2017-0324"
  );
  script_osvdb_id(
    152154,
    152155,
    152156,
    152158,
    152159,
    152160,
    152161,
    152162,
    152163,
    152164,
    152165,
    152166,
    152167,
    152180,
    152181
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 375.x < 376.67 / 378.x < 378.52 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 375.x prior to 376.67 or 378.x prior to 378.52.
It is, therefore, affected by multiple vulnerabilities :

  - Multiple overflow conditions exist in the kernel mode
    layer handler (nvlddmkm.sys) for DxgkDdiEscape due to a
    failure to properly calculate the input buffer size. A
    local attacker can exploit these to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-0308, CVE-2017-0324)

  - Multiple integer overflow conditions exist in the kernel
    mode layer handler that allow a local attacker to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2017-0309)

  - A flaw exists in the kernel mode layer handler due to
    improper access controls that allows a local attacker to
    cause a denial of service condition. (CVE-2017-0310)

  - A flaw exists in the kernel mode layer handler due to
    improper access controls that allows a local attacker to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-0311)

  - An overflow condition exists in the kernel mode layer
    handler for DxgDdiEscape ID 0x100008B due to improper
    validation of input before setting the limits for a
    loop. A local attacker can exploit this to cause a
    denial of service condition or potentially gain elevated
    privileges. (CVE-2017-0312)

  - Multiple out-of-bounds write flaws exist within the
    DxgkDdiSubmitCommandVirtual() function in the kernel
    mode layer handler due to improper validation of certain
    size and length values. A local attacker can exploit
    these to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-0313,
    CVE-2017-0314)

  - A flaw exists in the kernel mode layer handler for
    DxgkDdiEscape due to accessing an invalid object
    pointer that allows a local attacker to execute
    arbitrary code. (CVE-2017-0315)

  - A flaw exists in the NVIDIA GPU and GeForce Experience
    Installer due to improper file permissions on the
    package extraction path. A local attacker can exploit
    this to manipulate extracted files and thereby
    potentially gain elevated privileges. (CVE-2017-0317)

  - Multiple flaws exist in the kernel mode layer handler due
    to improper handling of unspecified values that allow a
    local attacker to cause a denial of service condition.
    (CVE-2017-0319, CVE-2017-0320)

  - Multiple NULL pointer dereference flaws exist in the
    kernel mode layer handler due to improper validation of
    certain input. A local attacker can exploit these to
    cause a denial of service condition or potentially
    execute arbitrary code. (CVE-2017-0321, CVE-2017-0323)

  - An array-indexing error exists in the kernel mode layer
    handler due to improper validation of certain input. A
    local attacker can exploit this to cause a denial of
    service condition or gain elevated privileges.
    (CVE-2017-0322)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4398");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 376.67 / 378.52 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

report = '';

foreach kb (keys(kbs))
{
  name = kbs[kb];
  # only check NVIDIA drivers
  if ("NVIDIA" >!< name) continue;

  nvidia_found = TRUE;
  id = kb - kb_base - '/Name';
  version = get_kb_item_or_exit(kb_base + id + '/Version');
  driver_date = get_kb_item_or_exit(kb_base + id + '/DriverDate');

  disp_driver_date = driver_date;

  # convert to something we can pass to ver_compare (YYYY.MM.DD)
  driver_date = split(driver_date, sep:'/', keep:FALSE);
  driver_date = driver_date[2] + '.' + driver_date[0] + '.' + driver_date[1];

  fix = '';
  note = '';

  # R375 Branch includes 375.x, 376.x
  if (version =~ "^37[56]\." && "Tesla" >!< name && ver_compare(ver:version, fix:"376.67", strict:FALSE) == -1)
    fix = '376.67';
  if (version =~ "^37[56]\." && "Tesla" >< name && ver_compare(ver:version, fix:"376.84", strict:FALSE) == -1)
    fix = '376.84';

  # R378 Branch
  if (version =~ "^378\." && ver_compare(ver:version, fix:"378.52", strict:FALSE) == -1)
    fix = '378.52';

  if (!empty(fix))
  {
    order = make_list('Device name','Driver version','Driver date','Fixed version');
    report = make_array(
      order[0],name,
      order[1],version,
      order[2],disp_driver_date,
      order[3],fix
      );

    if (!empty(note))
    {
      report['Note'] = note;
      order = make_list(order, 'Note');
    }
    report = report_items_str(report_items:report, ordered_fields:order);
  }
}

if (!nvidia_found) exit(0, 'No NVIDIA display drivers were found.');

if (!empty(report))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
else
  exit(0, "No vulnerable NVIDIA display drivers were found.");
