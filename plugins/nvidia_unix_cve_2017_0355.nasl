#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100258);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/18 14:17:41 $");

  script_cve_id(
    "CVE-2017-0350",
    "CVE-2017-0351",
    "CVE-2017-0352"
  );
  script_bugtraq_id(
    98393,
    98475
  );
  script_osvdb_id(
    157325,
    157326,
    157327
  );
  script_xref(name:"IAVA", value:"2017-A-0151");

  script_name(english:"NVIDIA Linux GPU Display Driver 375.x < 375.66 / 381.x < 381.22 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Linux host is 375.x prior to 375.66 or 381.x prior to 381.22. It is,
therefore, affected by multiple vulnerabilities:

  - A flaw exists in the kernel mode layer handler due to
    improper validation of user-supplied input before it
    is used in offset calculations. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges. (CVE-2017-0350)

  - A NULL pointer dereference flaw exists in the kernel
    mode layer handler due to improper validation of
    user-supplied input. A local attacker can exploit this
    to cause a denial of service condition or potentially to
    gain elevated privileges. (CVE-2017-0351)

  - A flaw exists in the GPU firmware due to incorrect
    access control that may allow CPU software to access
    sensitive GPU control registers. A local attacker can
    exploit this to gain elevated privileges.
    (CVE-2017-0352)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4462");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 375.66 / 381.22 or later
in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("NVIDIA_UNIX_Driver/Version");

fix = NULL;

if (version =~ "^381\." && ver_compare(ver:version, fix:"381.22", strict:FALSE) == -1)
  fix = "381.22";
else if (version =~ "^375\." && ver_compare(ver:version, fix:"375.66", strict:FALSE) == -1)
  fix = "375.66";

if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "NVIDIA UNIX Driver", version);

report = '\n  Installed driver version : ' + version +
         '\n  Fixed driver version     : ' + fix;

security_report_v4(severity:SECURITY_HOLE, port:0, extra: report);
