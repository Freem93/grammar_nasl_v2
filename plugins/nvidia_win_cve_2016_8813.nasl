#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95370);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/27 16:20:34 $");

  script_cve_id(
    "CVE-2016-8813",
    "CVE-2016-8814",
    "CVE-2016-8815",
    "CVE-2016-8816",
    "CVE-2016-8817",
    "CVE-2016-8818",
    "CVE-2016-8819",
    "CVE-2016-8820"
  );
  script_osvdb_id(
    147535,
    147536,
    147537,
    147538,
    147539,
    147540,
    147541,
    147542
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 34x.x < 342.00 / 367.x < 369.73 / 367.x < 369.71 (GRID) / 375.x < 375.63 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 34x.x prior to 342.00, 367.x prior to 369.73, 367.x
prior to 369.71 (GRID), or 375.x prior to 375.63. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple privilege escalation vulnerabilities exist in
    the kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to a NULL pointer dereference flaw. A
    local attacker can exploit this to cause a denial of
    service condition or an escalation of privileges.
    (CVE-2016-8813, CVE-2016-8814)

  - Multiple privilege escalation vulnerabilities exist in
    the kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper validation of user-supplied
    input used for the index to an array. A local attacker
    can exploit this to cause a denial of service condition
    or an escalation of privileges. (CVE-2016-8815,
    CVE-2016-8815)

  - A privilege escalation vulnerability exists in the
    kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper validation of user-supplied
    input to the memcpy() function. A local attacker can
    exploit this to cause a buffer overflow, resulting in a
    denial of service condition or an escalation of
    privileges. (CVE-2016-8817)

  - A privilege escalation vulnerability exists in the
    kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper validation of user-supplied
    input. A local attacker can exploit this to cause a
    denial of service condition or an escalation of
    privileges. (CVE-2016-8818)

  - A privilege escalation vulnerability exists in the
    kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper handling of objects in
    memory. A local attacker can exploit this to cause a
    denial of service condition or an escalation of
    privileges. (CVE-2016-8819)

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape due to a failure to check a
    function return value. A local attacker can exploit this
    to disclose sensitive information or cause a denial of
    service condition. (CVE-2016-8820)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4257");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 342.00 / 369.73 /
369.71 (GRID) / 375.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");

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
  if (version =~ "^34[012]\." && ver_compare(ver:version, fix:"342.00", strict:FALSE) == -1)
  {
    fix = '342.00';
    note = 'Only GeForce GPUs with Tesla architecture are affected.';
  }

  # R367 Branch includes 367.x, 368.x, 369.x
  if (version =~ "^36[7-9]\." && ver_compare(ver:version, fix:"369.73", strict:FALSE) == -1)
  {
    # potential FP if 369.71 or 369.72
    if (version =~ "^369\.7[12]$")
    {
      fix = '369.73';
      note = 'GRID Series products not affected in this case.';
    }
    else
      fix = '369.71 (GRID) / 369.73';
  }

  # R375 Branch
  if (version =~ "^375\." && ver_compare(ver:version, fix:"375.63", strict:FALSE) == -1)
    fix = '375.63';

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
