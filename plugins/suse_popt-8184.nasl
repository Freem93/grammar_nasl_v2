#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59984);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/07/17 10:56:12 $");

  script_name(english:"SuSE 10 Security Update : RPM (ZYPP Patch Number 8184)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security vulnerabilities were reported in RPM which could
have been exploited via specially crafted RPM files to cause a denial
of service (application crash) or potentially allow attackers to
execute arbitrary code.

Additionally, a non-security issue was fixed that could cause a
division by zero in cycles calculation under rare circumstances."
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8184.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"popt-1.7-271.46.16")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"popt-devel-1.7-271.46.16")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"rpm-4.4.2-43.46.16")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"rpm-devel-4.4.2-43.46.16")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"i586", reference:"rpm-python-4.4.2-43.46.16")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"popt-1.7-271.46.16")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"popt-devel-1.7-271.46.16")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"rpm-4.4.2-43.46.16")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"rpm-devel-4.4.2-43.46.16")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"i586", reference:"rpm-python-4.4.2-43.46.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
