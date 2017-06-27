#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84621);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/24 16:00:47 $");

  script_cve_id("CVE-2015-3625");
  script_osvdb_id(123644);
  script_xref(name:"IAVB", value:"2015-B-0094");

  script_name(english:"NVIDIA Graphics Driver Pointer Dereference Privilege Escalation (Unix / Linux)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a driver installed that is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA graphics driver installed on the remote host is affected by
a privilege escalation vulnerability, due to a pointer dereferencing
flaw in the kernel module, which allows a local attacker to gain
complete control of the system.");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/3693");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate video driver according to the vendor's
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

uname = get_kb_item_or_exit("Host/uname");

if ("FreeBSD" >!< uname)
  audit(AUDIT_OS_NOT, "FreeBSD");


fix = NULL;
extra = '';

if (version =~ "^352\." && ver_compare(ver:version, fix:"352.09", strict:FALSE) == -1)
  fix = "352.09";
else if (version =~ "^346\." && ver_compare(ver:version, fix:"346.72", strict:FALSE) == -1)
  fix = "346.72";

if(report_paranoia > 1 && (
      version == "349.16" ||
      version == "343.36" ||
      version == "340.76" ||
      version == "337.25" ||
      version == "334.21" ||
      version == "331.113" ||
      version == "304.125"))
{
 fix = "See Vendor";
 extra = '\nThe reported version has patches available; however, Nessus' +
         '\nis unable to test for their presence.';
}

if(!fix)
  audit(AUDIT_INST_VER_NOT_VULN, "NVIDIA UNIX Driver", version);

items = make_array("Installed driver version", version,
                   "Fixed driver version", fix
                  );

order = make_list("Installed driver version", "Fixed driver version");
report = report_items_str(report_items:items, ordered_fields:order);

report += extra;

security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);

