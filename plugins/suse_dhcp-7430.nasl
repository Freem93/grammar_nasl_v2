#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57179);
  script_version ("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/17 11:05:45 $");

  script_cve_id("CVE-2011-0997");

  script_name(english:"SuSE 10 Security Update : dhcp (ZYPP Patch Number 7430)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A rogue DHCP server could instruct clients to use a host name that
contains shell meta characters. Since many scripts in the system do
not expect unusal characters in the system's host name the DHCP client
needs to sanitize the host name offered by the server. (CVE-2011-0997)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-0997.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7430.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"dhcp-3.0.7-7.11.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"dhcp-client-3.0.7-7.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dhcp-3.0.7-7.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dhcp-client-3.0.7-7.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dhcp-devel-3.0.7-7.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dhcp-relay-3.0.7-7.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"dhcp-server-3.0.7-7.11.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
