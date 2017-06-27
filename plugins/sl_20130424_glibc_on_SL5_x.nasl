#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(66227);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914");

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
"It was found that getaddrinfo() did not limit the amount of stack
memory used during name resolution. An attacker able to make an
application resolve an attacker-controlled hostname or IP address
could possibly cause the application to exhaust all stack memory and
crash. (CVE-2013-1914)

A flaw was found in the regular expression matching routines that
process multibyte character input. If an application utilized the
glibc regular expression matching mechanism, an attacker could provide
specially crafted input that, when processed, would cause the
application to crash. (CVE-2013-0242)

This update also fixes the following bugs :

  - The improvements made in a previous update to the
    accuracy of floating point functions in the math library
    caused performance regressions for those functions. The
    performance regressions were analyzed and a fix was
    applied that retains the current accuracy but reduces
    the performance penalty to acceptable levels.

  - It was possible that a memory location freed by the
    localization code could be accessed immediately after,
    resulting in a crash. The fix ensures that the
    application does not crash by avoiding the invalid
    memory access."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1304&L=scientific-linux-errata&T=0&P=2612
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad5066e7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"glibc-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-common-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-debuginfo-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-debuginfo-common-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-devel-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-headers-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"SL5", reference:"glibc-utils-2.5-107.el5_9.4")) flag++;
if (rpm_check(release:"SL5", reference:"nscd-2.5-107.el5_9.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
