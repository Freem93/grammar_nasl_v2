#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100259);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/18 14:17:41 $");

  script_cve_id(
    "CVE-2017-0341",
    "CVE-2017-0342",
    "CVE-2017-0343",
    "CVE-2017-0344",
    "CVE-2017-0345",
    "CVE-2017-0346",
    "CVE-2017-0347",
    "CVE-2017-0348",
    "CVE-2017-0349",
    "CVE-2017-0353",
    "CVE-2017-0354",
    "CVE-2017-0355"
  );
  script_bugtraq_id(
    98393,
    98475
  );
  script_osvdb_id(
    157300,
    157304,
    157305,
    157306,
    157307,
    157308,
    157309,
    157323,
    157324,
    157328,
    157329,
    157330
  );
  script_xref(name:"IAVA", value:"2017-A-0151");

  script_name(english:"NVIDIA Windows GPU Display Driver 375.x < 377.35 / 382.x < 382.05 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 375.x prior to 377.35 or 382.x prior to 382.05. It is,
therefore, affected by multiple vulnerabilities :

  - An uninitialized pointer flaw exists in the kernel mode
    layer (nvlddmkm.sys) handler for DxgDdiEscape due to
    improper validation of user-supplied input. A local
    attacker can exploit this to cause a denial of service
    condition or potentially to gain elevated privileges.
    (CVE-2017-0341)

  - An out-of-bounds access error exists in the kernel mode
    layer (nvlddmkm.sys) handler due to certain incorrect
    calculations. A local attacker can exploit this to cause
    a denial of service condition or potentially to gain
    elevated privileges. (CVE-2017-0342)

  - A race condition exists in the kernel mode layer
    (nvlddmkm.sys) handler due to improper synchronization
    of certain functions. A local attacker can exploit this
    to cause a denial of service condition or potentially to
    gain elevated privileges. (CVE-2017-0343)

  - An unspecified flaw exists in the kernel mode layer
    (nvlddmkm.sys) handler for DxgDdiEscape that allows a
    local attacker to access arbitrary physical memory and
    gain elevated privileges. (CVE-2017-0344)

  - An out-of-bounds access error exists in the kernel mode
    layer (nvlddmkm.sys) handler for DxgDdiEscape due to
    improper validation of user-supplied array size input. A
    local attacker can exploit this to cause a denial of
    service condition or potentially to gain elevated
    privileges. (CVE-2017-0345)

  - A buffer overflow condition exists in the kernel mode
    layer (nvlddmkm.sys) handler for DxgDdiEscape due to
    improper validation of user-supplied input. A local
    attacker can exploit this to cause a denial of service
    condition or potentially to gain elevated privileges.
    (CVE-2017-0346)

  - An array-indexing error exists in the kernel mode layer
    (nvlddmkm.sys) handler for DxgkDdiEscape due to improper
    validation of user-supplied input. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges. (CVE-2017-0347)

  - A NULL pointer dereference flaw exists in the kernel
    mode layer (nvlddmkm.sys) handler due to improper
    validation of user-supplied input. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges.
    (CVE-2017-0348)

  - An invalid pointer flaw exists in the kernel mode layer
    (nvlddmkm.sys) handler for DxgkDdiEscape due to improper
    validation of a user-supplied pointer before it is
    dereferenced for a write operation. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges. (CVE-2017-0349)

  - A flaw exists in the kernel mode layer handler for
    DxgDdiEscape due to the driver improperly locking on
    certain conditions. A local attacker can exploit this to
    cause a denial of service condition. (CVE-2017-0353)

  - A flaw exists in the kernel mode layer handler for
    DxgkDdiEscape where a call to certain functions
    requiring lower IRQL can be made under raised IRQL. A
    local attacker can exploit this to cause a denial of
    service condition. (CVE-2017-0354)

  - A flaw exists in the kernel mode layer handler for
    DxgkDdiEscape due to accessing paged memory while
    holding a spin lock. A local attacker can exploit this
    to cause a denial of service condition.
    (CVE-2017-0355)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4462");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 377.35 / 382.05 or
later in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

  # R375 Branch includes 375.x, 376.x, 377.x
  if (version =~ "^37[567]\." && ver_compare(ver:version, fix:"377.35", strict:FALSE) == -1)
    fix = '377.35';

  # R381 Branch includes 381.x, 382.x
  if (version =~ "^38[12]\." && ver_compare(ver:version, fix:"382.05", strict:FALSE) == -1)
    fix = '382.05';

  if (!empty(fix))
  {
    order = make_list('Device name','Driver version','Driver date','Fixed version');
    report = make_array(
      order[0],name,
      order[1],version,
      order[2],disp_driver_date,
      order[3],fix
      );

    report = report_items_str(report_items:report, ordered_fields:order);
    break;
  }
}

if (!nvidia_found) exit(0, 'No NVIDIA display drivers were found.');

if (!empty(report))
  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
else
  exit(0, "No vulnerable NVIDIA display drivers were found.");
