#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82262);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/26 13:38:48 $");

  script_cve_id("CVE-2014-9657", "CVE-2014-9658", "CVE-2014-9660", "CVE-2014-9661", "CVE-2014-9663", "CVE-2014-9664", "CVE-2014-9667", "CVE-2014-9669", "CVE-2014-9670", "CVE-2014-9671", "CVE-2014-9673", "CVE-2014-9674", "CVE-2014-9675");

  script_name(english:"Scientific Linux Security Update : freetype on SL6.x, SL7.x i386/x86_64");
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
"Multiple integer overflow flaws and an integer signedness flaw,
leading to heap-based buffer overflows, were found in the way FreeType
handled Mac fonts. If a specially crafted font file was loaded by an
application linked against FreeType, it could cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2014-9673, CVE-2014-9674)

Multiple flaws were found in the way FreeType handled fonts in various
formats. If a specially crafted font file was loaded by an application
linked against FreeType, it could cause the application to crash or,
possibly, disclose a portion of the application memory.
(CVE-2014-9657, CVE-2014-9658, CVE-2014-9660, CVE-2014-9661,
CVE-2014-9663, CVE-2014-9664, CVE-2014-9667, CVE-2014-9669,
CVE-2014-9670, CVE-2014-9671, CVE-2014-9675)

The X server must be restarted (log out, then log back in) for this
update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=1645
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?36c5cf70"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"freetype-2.3.11-15.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"freetype-debuginfo-2.3.11-15.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"freetype-demos-2.3.11-15.el6_6.1")) flag++;
if (rpm_check(release:"SL6", reference:"freetype-devel-2.3.11-15.el6_6.1")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freetype-2.4.11-10.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freetype-debuginfo-2.4.11-10.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freetype-demos-2.4.11-10.el7_1.1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"freetype-devel-2.4.11-10.el7_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
