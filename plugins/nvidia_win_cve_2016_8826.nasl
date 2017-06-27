#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96002);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/27 16:20:34 $");

  script_cve_id(
    "CVE-2016-8821",
    "CVE-2016-8822",
    "CVE-2016-8823",
    "CVE-2016-8824",
    "CVE-2016-8825",
    "CVE-2016-8826"
  );
  script_bugtraq_id(
    94918,
    94956,
    94957
  );
  script_osvdb_id(
    148773,
    148774,
    148775,
    148776,
    148777,
    148778
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 340.x < 342.01 / 375.x < 376.33 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 340.x prior to 342.01 or 375.x prior to 376.33. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape due to improper access
    controls. A local attacker can exploit this to access
    arbitrary memory and thereby gain elevated privileges.
    (CVE-2016-8821)

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape IDs 0x600000E, 0x600000F, and
    0x6000010 due to improper validation of user-supplied
    input that is used as an index to an internal array. A
    local attacker can exploit this to corrupt memory,
    resulting in a denial of service condition or an
    escalation of privileges. (CVE-2016-8822)

  - Multiple buffer overflow conditions exist in the kernel
    mode layer (nvlddmkm.sys) handler for DxgDdiEscape due
    to improper validation of an input buffer size. A local
    attacker can exploit these to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-8823, CVE-2016-8825)

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape due to improper access
    controls. A local attacker can exploit this to write to
    restricted portions of the registry and thereby gain
    elevated privileges. (CVE-2016-8824)

  - A flaw exists in the nvlddmkm.sys driver that allows a
    local attacker to cause GPU interrupt saturation,
    resulting in a denial of service condition.
    (CVE-2016-8826)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4278");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 342.01 / 376.33 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

  # R340 Branch includes 340.x, 341.x, 342.x
  if (version =~ "^34[012]\." && ver_compare(ver:version, fix:"342.01", strict:FALSE) == -1)
  {
    fix = '342.01';
    note = 'Only GeForce GPUs with Tesla architecture are affected.';
  }

  # R375 Branch includes 375.x, 376.x
  if (version =~ "^37[56]\." && ver_compare(ver:version, fix:"376.33", strict:FALSE) == -1)
    fix = '376.33';

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
