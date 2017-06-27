#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61243);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/04 23:38:20 $");

  script_cve_id("CVE-2009-5029", "CVE-2009-5064", "CVE-2010-0296", "CVE-2010-0830", "CVE-2011-1071", "CVE-2011-1089", "CVE-2011-1095", "CVE-2011-4609");

  script_name(english:"Scientific Linux Security Update : glibc on SL4.x i386/x86_64");
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
"The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library read timezone files. If a
carefully-crafted timezone file was loaded by an application linked
against glibc, it could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2009-5029)

A flaw was found in the way the ldd utility identified dynamically
linked libraries. If an attacker could trick a user into running ldd
on a malicious binary, it could result in arbitrary code execution
with the privileges of the user running ldd. (CVE-2009-5064)

It was discovered that the glibc addmntent() function, used by various
mount helper utilities, did not sanitize its input properly. A local
attacker could possibly use this flaw to inject malformed lines into
the mtab (mounted file systems table) file via certain setuid mount
helpers, if the attacker were allowed to mount to an arbitrary
directory under their control. (CVE-2010-0296)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library loaded ELF (Executable and Linking
Format) files. If a carefully-crafted ELF file was loaded by an
application linked against glibc, it could cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2010-0830)

It was discovered that the glibc fnmatch() function did not properly
restrict the use of alloca(). If the function was called on
sufficiently large inputs, it could cause an application using
fnmatch() to crash or, possibly, execute arbitrary code with the
privileges of the application. (CVE-2011-1071)

It was found that the glibc addmntent() function, used by various
mount helper utilities, did not handle certain errors correctly when
updating the mtab (mounted file systems table) file. If such utilities
had the setuid bit set, a local attacker could use this flaw to
corrupt the mtab file. (CVE-2011-1089)

It was discovered that the locale command did not produce properly
escaped output as required by the POSIX specification. If an attacker
were able to set the locale environment variables in the environment
of a script that performed shell evaluation on the output of the
locale command, and that script were run with different privileges
than the attacker's, it could execute arbitrary code with the
privileges of the script. (CVE-2011-1095)

An integer overflow flaw was found in the glibc fnmatch() function. If
an attacker supplied a long UTF-8 string to an application linked
against glibc, it could cause the application to crash.
(CVE-2011-1659)

A denial of service flaw was found in the remote procedure call (RPC)
implementation in glibc. A remote attacker able to open a large number
of connections to an RPC service that is using the RPC implementation
from glibc, could use this flaw to make that service use an excessive
amount of CPU time. (CVE-2011-4609)

This update also fixes the following bug :

  - When using an nscd package that is a different version
    than the glibc package, the nscd service could fail to
    start. This update makes the nscd package require a
    specific glibc version to prevent this problem.

Users should upgrade to these updated packages, which resolve these
issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=2559
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c5ec1fd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
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
if (rpm_check(release:"SL4", reference:"glibc-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"glibc-common-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"glibc-debuginfo-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"glibc-debuginfo-common-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"glibc-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"glibc-headers-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"glibc-profile-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"glibc-utils-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"nptl-devel-2.3.4-2.57")) flag++;
if (rpm_check(release:"SL4", reference:"nscd-2.3.4-2.57")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
