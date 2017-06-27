#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94575);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id(
    "CVE-2016-7382",
    "CVE-2016-7389"
  );
  script_osvdb_id(
    146441,
    146442
  );
  script_name(english:"NVIDIA Linux GPU Display Driver 304.x < 304.132 / 340.x < 340.98 / 361.93.x < 361.93.03 / 367.x < 367.55 / 370.x < 370.28 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Linux host is 304.x prior to 304.132, 340.x prior to 340.98, 361.93.x
prior to 361.93.03, 367.x prior to 367.55, or 370.x prior to 370.28.
It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the kernel-mode layer (nvidia.ko)
    handler related to missing permission checks. A local
    attacker can exploit this to disclose arbitrary memory
    contents and gain elevated privileges. (CVE-2016-7382)

  - A flaw exists in the kernel-mode layer (nvidia.ko)
    handler related to improper memory mapping. A local
    attacker can exploit this to disclose arbitrary memory
    contents and gain elevated privileges. (CVE-2016-7389)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4246");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 304.132 / 340.98 /
361.93.03 / 367.55 / 370.28 or later in accordance with the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("NVIDIA_UNIX_Driver/Version");

fix = NULL;

if (version =~ "^370\." && ver_compare(ver:version, fix:"370.28", strict:FALSE) == -1)
  fix = "370.28";
else if (version =~ "^367\." && ver_compare(ver:version, fix:"367.55", strict:FALSE) == -1)
  fix = "367.55";
else if (version =~ "^340\." && ver_compare(ver:version, fix:"340.98", strict:FALSE) == -1)
  fix = "340.98";
else if (version =~ "^304\." && ver_compare(ver:version, fix:"304.132", strict:FALSE) == -1)
  fix = "304.132";
else if (version =~ "^361\.93\." && ver_compare(ver:version, fix:"361.93.03", strict:FALSE) == -1)
  fix = "361.93.03";

if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "NVIDIA UNIX Driver", version);

report = '\n  Installed driver version : ' + version +
         '\n  Fixed driver version     : ' + fix;

security_report_v4(severity:SECURITY_HOLE, port:0, extra: report);
