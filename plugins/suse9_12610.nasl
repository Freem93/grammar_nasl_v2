#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46169);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/04/23 18:21:33 $");

  script_cve_id("CVE-2010-0098", "CVE-2010-1311");

  script_name(english:"SuSE9 Security Update : clamav (YOU Patch Number 12610)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Specially crafted CAB archives could crash clamav (CVE-2010-1311) or
bypass virus detection (CVE-2010-0098). clamav has been updated to
version 0.96 which fixes those issues.

Citing freshmeat.net :

This Release introduces new malware detection mechanisms and other
significant improvements to the scan engine. Key features include the
bytecode interpreter, heuristic improvements, signature improvements,
support for new archives, support for new executable file formats,
support for UPX 3.0, performance improvements and memory
optimizations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1311.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12610.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"clamav-0.96-2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
