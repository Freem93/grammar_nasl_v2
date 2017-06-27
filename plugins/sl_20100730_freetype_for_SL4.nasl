#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60825);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 00:00:32 $");

  script_cve_id("CVE-2010-2498", "CVE-2010-2499", "CVE-2010-2500", "CVE-2010-2519", "CVE-2010-2527", "CVE-2010-2541");

  script_name(english:"Scientific Linux Security Update : freetype for SL4 , SL5");
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
"An invalid memory management flaw was found in the way the FreeType
font engine processed font files. If a user loaded a carefully-crafted
font file with an application linked against FreeType, it could cause
the application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2010-2498)

An integer overflow flaw was found in the way the FreeType font engine
processed font files. If a user loaded a carefully-crafted font file
with an application linked against FreeType, it could cause the
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2010-2500)

Several buffer overflow flaws were found in the way the FreeType font
engine processed font files. If a user loaded a carefully-crafted font
file with an application linked against FreeType, it could cause the
application to crash or, possibly, execute arbitrary code with the
privileges of the user running the application. (CVE-2010-2499,
CVE-2010-2519)

Several buffer overflow flaws were found in the FreeType demo
applications. If a user loaded a carefully-crafted font file with a
demo application, it could cause the application to crash or,
possibly, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-2527, CVE-2010-2541)

Note: All of the issues in this erratum only affect the FreeType 2
font engine.

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues. The X server must be
restarted (log out, then log back in) for this update to take effect.

File List"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1007&L=scientific-linux-errata&T=0&P=3474
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c267a1ec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"freetype-2.1.9-14.el4.8")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-debuginfo-2.1.9-14.el4.8")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-demos-2.1.9-14.el4.8")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-devel-2.1.9-14.el4.8")) flag++;
if (rpm_check(release:"SL4", reference:"freetype-utils-2.1.9-14.el4.8")) flag++;

if (rpm_check(release:"SL5", reference:"freetype-2.2.1-25.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"freetype-debuginfo-2.2.1-25.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"freetype-demos-2.2.1-25.el5_5")) flag++;
if (rpm_check(release:"SL5", reference:"freetype-devel-2.2.1-25.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
