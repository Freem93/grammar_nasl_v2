#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61111);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-2895");

  script_name(english:"Scientific Linux Security Update : freetype on SL4.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"FreeType is a free, high-quality, portable font engine that can open
and manage font files. It also loads, hints, and renders individual
glyphs efficiently. These packages provide both the FreeType 1 and
FreeType 2 font engines.

A buffer overflow flaw was found in the way the FreeType library
handled malformed font files compressed using UNIX compress. If a user
loaded a specially crafted compressed font file with an application
linked against FreeType, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2011-2895)

Note: This issue only affects the FreeType 2 font engine.

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct this issue. The X server must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1108&L=scientific-linux-errata&T=0&P=1663
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05b05c7a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL4", reference:"freetype-2.1.9-19.el4")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-demos-2.1.9-19.el4")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-devel-2.1.9-19.el4")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-utils-2.1.9-19.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
