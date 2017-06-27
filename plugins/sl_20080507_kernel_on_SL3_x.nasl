#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60393);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2006-4814", "CVE-2007-5001", "CVE-2007-6151", "CVE-2007-6206", "CVE-2008-0007", "CVE-2008-1367", "CVE-2008-1375", "CVE-2008-1669");

  script_name(english:"Scientific Linux Security Update : kernel on SL3.x i386/x86_64");
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
"These updated packages fix the following security issues :

  - the absence of a protection mechanism when attempting to
    access a critical section of code has been found in the
    Linux kernel open file descriptors control mechanism,
    fcntl. This could allow a local unprivileged user to
    simultaneously execute code, which would otherwise be
    protected against parallel execution. As well, a race
    condition when handling locks in the Linux kernel fcntl
    functionality, may have allowed a process belonging to a
    local unprivileged user to gain re-ordered access to the
    descriptor table. (CVE-2008-1669, Important)

  - the absence of a protection mechanism when attempting to
    access a critical section of code, as well as a race
    condition, have been found in the Linux kernel file
    system event notifier, dnotify. This could allow a local
    unprivileged user to get inconsistent data, or to send
    arbitrary signals to arbitrary system processes.
    (CVE-2008-1375, Important)

  - when accessing kernel memory locations, certain Linux
    kernel drivers registering a fault handler did not
    perform required range checks. A local unprivileged user
    could use this flaw to gain read or write access to
    arbitrary kernel memory, or possibly cause a kernel
    crash. (CVE-2008-0007, Important)

  - a flaw was found when performing asynchronous input or
    output operations on a FIFO special file. A local
    unprivileged user could use this flaw to cause a kernel
    panic. (CVE-2007-5001, Important)

  - a flaw was found in the way core dump files were
    created. If a local user could get a root-owned process
    to dump a core file into a directory, which the user has
    write access to, they could gain read access to that
    core file. This could potentially grant unauthorized
    access to sensitive information. (CVE-2007-6206,
    Moderate)

  - a buffer overflow was found in the Linux kernel ISDN
    subsystem. A local unprivileged user could use this flaw
    to cause a denial of service. (CVE-2007-6151, Moderate)

  - a race condition found in the mincore system core could
    allow a local user to cause a denial of service (system
    hang). (CVE-2006-4814, Moderate)

  - it was discovered that the Linux kernel handled string
    operations in the opposite way to the GNU Compiler
    Collection (GCC). This could allow a local unprivileged
    user to cause memory corruption. (CVE-2008-1367, Low)

As well, these updated packages fix the following bugs :

  - a bug, which caused long delays when unmounting mounts
    containing a large number of unused dentries, has been
    resolved.

  - in the previous kernel packages, the kernel was unable
    to handle certain floating point instructions on
    Itanium(R) architectures.

  - on certain Intel CPUs, the Translation Lookaside Buffer
    (TLB) was not flushed correctly, which caused machine
    check errors."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=74
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d51a1cec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(16, 94, 119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"kernel-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-doc-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-unsupported-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-source-2.4.21-57.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-unsupported-2.4.21-57.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
