#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61692);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/08/29 11:06:16 $");

  script_cve_id("CVE-2012-3480");

  script_name(english:"Scientific Linux Security Update : glibc on SL5.x i386/x86_64");
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
"The glibc packages provide the standard C and standard math libraries
used by multiple programs on the system. Without these libraries, the
Linux system cannot function properly.

Multiple integer overflow flaws, leading to stack-based buffer
overflows, were found in glibc's functions for converting a string to
a numeric representation (strtod(), strtof(), and strtold()). If an
application used such a function on attacker controlled input, it
could cause the application to crash or, potentially, execute
arbitrary code. (CVE-2012-3480)

This update also fixes the following bug :

  - Previously, logic errors in various mathematical
    functions, including exp, exp2, expf, exp2f, pow, sin,
    tan, and rint, caused inconsistent results when the
    functions were used with the non-default rounding mode.
    This could also cause applications to crash in some
    cases. With this update, the functions now give correct
    results across the four different rounding modes.

All users of glibc are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=2838
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cf707bb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/28");
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
if (rpm_check(release:"SL5", reference:"glibc-2.5-81.el5_8.7")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-common-2.5-81.el5_8.7")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-devel-2.5-81.el5_8.7")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-headers-2.5-81.el5_8.7")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-utils-2.5-81.el5_8.7")) flag++;
if (rpm_check(release:"SL5", reference:"nscd-2.5-81.el5_8.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
