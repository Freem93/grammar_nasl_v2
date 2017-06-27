#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61284);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/04 23:38:20 $");

  script_cve_id("CVE-2012-0864");

  script_name(english:"Scientific Linux Security Update : glibc on SL6.x i386/x86_64");
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
Linux system cannot function correctly.

An integer overflow flaw was found in the implementation of the printf
functions family. This could allow an attacker to bypass
FORTIFY_SOURCE protections and execute arbitrary code using a format
string flaw in an application, even though these protections are
expected to limit the impact of such flaws to an application abort.
(CVE-2012-0864)

This update also fixes the following bugs :

  - Previously, the dynamic loader generated an incorrect
    ordering for initialization according to the ELF
    specification. This could result in incorrect ordering
    of DSO constructors and destructors. With this update,
    dependency resolution has been fixed.

  - Previously, locking of the main malloc arena was
    incorrect in the retry path. This could result in a
    deadlock if an sbrk request failed. With this update,
    locking of the main arena in the retry path has been
    fixed. This issue was exposed by a bug fix provided in a
    previous update.

  - Calling memcpy with overlapping arguments on certain
    processors would generate unexpected results. While such
    code is a clear violation of ANSI/ISO standards, this
    update restores prior memcpy behavior.

All users of glibc are advised to upgrade to these updated packages,
which contain patches to resolve these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=1602
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3279eee"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.47.el6_2.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
