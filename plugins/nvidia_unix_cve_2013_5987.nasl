#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72484);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/02/14 11:57:51 $");

  script_cve_id("CVE-2013-5987");
  script_bugtraq_id(64525);
  script_osvdb_id(100517);
  script_xref(name:"IAVB", value:"2014-B-0011");

  script_name(english:"NVIDIA Graphics Driver Unspecified Privilege Escalation (Unix / Linux)");
  script_summary(english:"Checks Driver Version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a driver installed that is affected by a local
privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has a driver installed that is affected by an
unspecified, local privilege escalation vulnerability.  Using the
vulnerability, it may be possible for a local attacker to gain complete
control of the system."
  );
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/3377");
  script_set_attribute(attribute:"solution", value:"Upgrade to the appropriate video driver per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/Unmanaged");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("NVIDIA_UNIX_Driver/Version");
get_kb_item_or_exit("NVIDIA_UNIX_Driver/Unmanaged");

if (version =~ "^331\." && ver_compare(ver:version, fix:"331.20", strict:FALSE) == -1)
  fix = "331.20";
else if (version =~ "^319\." && ver_compare(ver:version, fix:"319.72", strict:FALSE) == -1)
  fix = "319.72";
else if (version =~ "^304\." && ver_compare(ver:version, fix:"304.116", strict:FALSE) == -1)
  fix = "304.116";
else 
  audit(AUDIT_INST_VER_NOT_VULN, "NVIDIA UNIX Driver", version);

if (report_verbosity > 0)
{
  report = '\n  Installed driver version : ' + version +
           '\n  Fixed driver version     : ' + fix + '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);

