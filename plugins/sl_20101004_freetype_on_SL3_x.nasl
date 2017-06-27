#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60861);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2010-2806", "CVE-2010-2808", "CVE-2010-3054", "CVE-2010-3311");

  script_name(english:"Scientific Linux Security Update : freetype on SL3.x, SL4.x, SL5.x i386/x86_64");
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
"It was discovered that the FreeType font rendering engine improperly
validated certain position values when processing input streams. If a
user loaded a specially crafted font file with an application linked
against FreeType, and the relevant font glyphs were subsequently
rendered with the X FreeType library (libXft), it could trigger a
heap-based buffer overflow in the libXft library, causing the
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2010-3311)

A stack-based buffer overflow flaw was found in the way the FreeType
font rendering engine processed some PostScript Type 1 fonts. If a
user loaded a specially crafted font file with an application linked
against FreeType, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-2808) (SLF4 and SLF5 only)

An array index error was found in the way the FreeType font rendering
engine processed certain PostScript Type 42 font files. If a user
loaded a specially crafted font file with an application linked
against FreeType, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-2806)

A stack overflow flaw was found in the way the FreeType font rendering
engine processed PostScript Type 1 font files that contain nested
Standard Encoding Accented Character (seac) calls. If a user loaded a
specially crafted font file with an application linked against
FreeType, it could cause the application to crash. (CVE-2010-3054)

Note: All of the issues in this erratum only affect the FreeType 2
font engine.

The X server must be restarted (log out, then log back in) for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1010&L=scientific-linux-errata&T=0&P=78
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9de8a24b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/04");
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
if (rpm_check(release:"SL3", reference:"freetype-2.1.4-18.el3")) flag++;
if (rpm_check(release:"SL3", reference:"freetype-demos-2.1.4-18.el3")) flag++;
if (rpm_check(release:"SL3", reference:"freetype-devel-2.1.4-18.el3")) flag++;
if (rpm_check(release:"SL3", reference:"freetype-utils-2.1.4-18.el3")) flag++;

if (rpm_check(release:"SL4", reference:"freetype-2.1.9-17.el4.8")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-demos-2.1.9-17.el4.8")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-devel-2.1.9-17.el4.8")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-utils-2.1.9-17.el4.8")) flag++;

if (rpm_check(release:"SL5", reference:"freetype-2.2.1-28.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"freetype-demos-2.2.1-28.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"freetype-devel-2.2.1-28.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
