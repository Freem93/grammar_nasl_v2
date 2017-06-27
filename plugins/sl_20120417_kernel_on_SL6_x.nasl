#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61302);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2012-0879", "CVE-2012-1090", "CVE-2012-1097");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64");
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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - Numerous reference count leaks were found in the Linux
    kernel's block layer I/O context handling
    implementation. This could allow a local, unprivileged
    user to cause a denial of service. (CVE-2012-0879,
    Moderate)

  - A flaw was found in the Linux kernel's cifs_lookup()
    implementation. POSIX open during lookup should only be
    supported for regular files. When non-regular files (for
    example, a named (FIFO) pipe or other special files) are
    opened on lookup, it could cause a denial of service.
    (CVE-2012-1090, Moderate)

  - It was found that the Linux kernel's register set
    (regset) common infrastructure implementation did not
    check if the required get and set handlers were
    initialized. A local, unprivileged user could use this
    flaw to cause a denial of service by performing a
    register set operation with a ptrace() PTRACE_SETREGSET
    or PTRACE_GETREGSET request. (CVE-2012-1097, Moderate)

This update also fixes several bugs and adds various enhancements. The
system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=1355
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc92a67b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/17");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-220.13.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-220.13.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
