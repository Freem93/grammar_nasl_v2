#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87411);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/28 18:52:12 $");

  script_cve_id("CVE-2015-7869");
  script_osvdb_id(130643);

  script_name(english:"NVIDIA Graphics Driver NVAPI Support Layer Integer Overflow Privilege Escalation (Unix / Linux)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA graphics driver installed on the remote host is affected
by a privilege escalation vulnerability in the NVAPI support layer due
to multiple unspecified integer overflow conditions in the underlying
kernel mode driver. A local attacker can exploit this to gain access
to uninitialized or out-of-bounds memory, resulting in possible
information disclosure, denial of service, or the gaining of elevated
privileges.");
  # https://packetstormsecurity.com/files/134428/Ubuntu-Security-Notice-USN-2814-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a143cf56");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/3808");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate video driver version according to the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("NVIDIA_UNIX_Driver/Version");

fix = NULL;
extra = '';

if (version =~ "^358\." && ver_compare(ver:version, fix:"358.16", strict:FALSE) == -1)
  fix = "358.16";
else if (version =~ "^352\." && ver_compare(ver:version, fix:"352.63", strict:FALSE) == -1)
  fix = "352.63";
else if (version =~ "^340\." && ver_compare(ver:version, fix:"340.96", strict:FALSE) == -1)
  fix = "340.96";
else if (version =~ "^304\." && ver_compare(ver:version, fix:"304.131", strict:FALSE) == -1)
  fix = "304.131";


if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "NVIDIA UNIX Driver", version);

else if (report_verbosity > 0)
{
  report = '\n  Installed driver version : ' + version +
           '\n  Fixed driver version     : ' + fix +
           '\n' + extra;

  security_warning(port:0, extra:report);
}
else security_warning(0);

