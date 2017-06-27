#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61148);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/10/03 00:00:32 $");

  script_cve_id("CVE-2011-1160", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1833", "CVE-2011-2484", "CVE-2011-2496", "CVE-2011-2521", "CVE-2011-2723", "CVE-2011-2898", "CVE-2011-2918");

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

  - Flaws in the AGPGART driver implementation when handling
    certain IOCTL commands could allow a local user to cause
    a denial of service or escalate their privileges.
    (CVE-2011-1745, CVE-2011-2022, Important)

  - An integer overflow flaw in agp_allocate_memory() could
    allow a local user to cause a denial of service or
    escalate their privileges. (CVE-2011-1746, Important)

  - A race condition flaw was found in the Linux kernel's
    eCryptfs implementation. A local attacker could use the
    mount.ecryptfs_private utility to mount (and then
    access) a directory they would otherwise not have access
    to. Note: To correct this issue, a previous
    ecryptfs-utils update, which provides the user-space
    part of the fix, must also be installed. (CVE-2011-1833,
    Moderate)

  - A denial of service flaw was found in the way the
    taskstats subsystem handled the registration of process
    exit handlers. A local, unprivileged user could register
    an unlimited amount of these handlers, leading to
    excessive CPU time and memory use. (CVE-2011-2484,
    Moderate)

  - A flaw was found in the way mapping expansions were
    handled. A local, unprivileged user could use this flaw
    to cause a wrapping condition, triggering a denial of
    service. (CVE-2011-2496, Moderate)

  - A flaw was found in the Linux kernel's Performance
    Events implementation. It could falsely lead the NMI
    (Non-Maskable Interrupt) Watchdog to detect a lockup and
    panic the system. A local, unprivileged user could use
    this flaw to cause a denial of service (kernel panic)
    using the perf tool. (CVE-2011-2521, Moderate)

  - A flaw in skb_gro_header_slow() in the Linux kernel
    could lead to GRO (Generic Receive Offload) fields being
    left in an inconsistent state. An attacker on the local
    network could use this flaw to trigger a denial of
    service. GRO is enabled by default in all network
    drivers that support it. (CVE-2011-2723, Moderate)

  - A flaw was found in the way the Linux kernel's
    Performance Events implementation handled
    PERF_COUNT_SW_CPU_CLOCK counter overflow. A local,
    unprivileged user could use this flaw to cause a denial
    of service. (CVE-2011-2918, Moderate)

  - A flaw was found in the Linux kernel's Trusted Platform
    Module (TPM) implementation. A local, unprivileged user
    could use this flaw to leak information to user-space.
    (CVE-2011-1160, Low)

  - Flaws were found in the tpacket_rcv() and
    packet_recvmsg() functions in the Linux kernel. A local,
    unprivileged user could use these flaws to leak
    information to user-space. (CVE-2011-2898, Low)

This update also fixes various bugs and adds one enhancement.
Documentation for these changes will be available shortly from the
Technical Notes document linked to in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs and add
the enhancement noted in the Technical Notes. The system must be
rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1110&L=scientific-linux-errata&T=0&P=443
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f16ef6e2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-131.17.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-131.17.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
