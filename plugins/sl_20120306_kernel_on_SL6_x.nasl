#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61277);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347", "CVE-2011-4594", "CVE-2011-4611", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0207");

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

  - A buffer overflow flaw was found in the way the Linux
    kernel's XFS file system implementation handled links
    with overly long path names. A local, unprivileged user
    could use this flaw to cause a denial of service or
    escalate their privileges by mounting a specially
    crafted disk. (CVE-2011-4077, Moderate)

  - Flaws in ghash_update() and ghash_final() could allow a
    local, unprivileged user to cause a denial of service.
    (CVE-2011-4081, Moderate)

  - A flaw was found in the Linux kernel's Journaling Block
    Device (JBD). A local, unprivileged user could use this
    flaw to crash the system by mounting a specially crafted
    ext3 or ext4 disk. (CVE-2011-4132, Moderate)

  - It was found that the kvm_vm_ioctl_assign_device()
    function in the KVM (Kernel-based Virtual Machine)
    subsystem of a Linux kernel did not check if the user
    requesting device assignment was privileged or not. A
    local, unprivileged user on the host could assign unused
    PCI devices, or even devices that were in use and whose
    resources were not properly claimed by the respective
    drivers, which could result in the host crashing.
    (CVE-2011-4347, Moderate)

  - Two flaws were found in the way the Linux kernel's
    __sys_sendmsg() function, when invoked via the
    sendmmsg() system call, accessed user-space memory. A
    local, unprivileged user could use these flaws to cause
    a denial of service. (CVE-2011-4594, Moderate)

  - A flaw was found in the way the KVM subsystem of a Linux
    kernel handled PIT (Programmable Interval Timer) IRQs
    (interrupt requests) when there was no virtual interrupt
    controller set up. A local, unprivileged user on the
    host could force this situation to occur, resulting in
    the host crashing. (CVE-2011-4622, Moderate)

  - A flaw was found in the way the Linux kernel's XFS file
    system implementation handled on-disk Access Control
    Lists (ACLs). A local, unprivileged user could use this
    flaw to cause a denial of service or escalate their
    privileges by mounting a specially crafted disk.
    (CVE-2012-0038, Moderate)

  - A flaw was found in the way the Linux kernel's KVM
    hypervisor implementation emulated the syscall
    instruction for 32-bit guests. An unprivileged guest
    user could trigger this flaw to crash the guest.
    (CVE-2012-0045, Moderate)

  - A divide-by-zero flaw was found in the Linux kernel's
    igmp_heard_query() function. An attacker able to send
    certain IGMP (Internet Group Management Protocol)
    packets to a target system could use this flaw to cause
    a denial of service. (CVE-2012-0207, Moderate)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=1112
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6e1e050"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/06");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-220.7.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
