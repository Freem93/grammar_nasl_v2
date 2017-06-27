#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60746);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:08 $");

  script_cve_id("CVE-2010-0421");

  script_name(english:"Scientific Linux Security Update : pango on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"CVE-2010-0421 libpangoft2 segfaults on forged font files

An input sanitization flaw, leading to an array index error, was found
in the way the Pango font rendering library synthesized the Glyph
Definition (GDEF) table from a font's character map and the Unicode
property database. If an attacker created a specially crafted font
file and tricked a local, unsuspecting user into loading the font file
in an application that uses the Pango font rendering library, it could
cause that application to crash. (CVE-2010-0421)

After installing this update, you must restart your system or restart
your X session for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=1148
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d2eaf42"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/15");
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
if (rpm_check(release:"SL3", reference:"pango-1.2.5-10")) flag++;
if (rpm_check(release:"SL3", reference:"pango-devel-1.2.5-10")) flag++;

if (rpm_check(release:"SL4", reference:"evolution28-pango-1.14.9-13.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"evolution28-pango-devel-1.14.9-13.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"pango-1.6.0-16.el4_8")) flag++;
if (rpm_check(release:"SL4", reference:"pango-devel-1.6.0-16.el4_8")) flag++;

if (rpm_check(release:"SL5", reference:"pango-1.14.9-8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"pango-devel-1.14.9-8.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
