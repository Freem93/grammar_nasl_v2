#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(78851);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/11/04 14:19:38 $");

  script_cve_id("CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-4653", "CVE-2014-5077");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64");
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
"Security fixes :

  - A race condition flaw was found in the way the Linux
    kernel's KVM subsystem handled PIT (Programmable
    Interval Timer) emulation. A guest user who has access
    to the PIT I/O ports could use this flaw to crash the
    host. (CVE-2014-3611, Important)

  - A NULL pointer dereference flaw was found in the way the
    Linux kernel's Stream Control Transmission Protocol
    (SCTP) implementation handled simultaneous connections
    between the same hosts. A remote attacker could use this
    flaw to crash the system. (CVE-2014-5077, Important)

  - It was found that the Linux kernel's KVM subsystem did
    not handle the VM exits gracefully for the invept
    (Invalidate Translations Derived from EPT) and invvpid
    (Invalidate Translations Based on VPID) instructions. On
    hosts with an Intel processor and invept/invppid VM exit
    support, an unprivileged guest user could use these
    instructions to crash the guest. (CVE-2014-3645,
    CVE-2014-3646, Moderate)

  - A use-after-free flaw was found in the way the Linux
    kernel's Advanced Linux Sound Architecture (ALSA)
    implementation handled user controls. A local,
    privileged user could use this flaw to crash the system.
    (CVE-2014-4653, Moderate)

Bug fixes :

  - A known issue that could prevent Chelsio adapters using
    the cxgb4 driver from being initialized on IBM POWER8
    systems has been fixed. These adapters can now be used
    on IBM POWER8 systems as expected.

  - When bringing a hot-added CPU online, the kernel did not
    initialize a CPU mask properly, which could result in a
    kernel panic. This update corrects the bug by ensuring
    that the CPU mask is properly initialized and the
    correct NUMA node selected.

  - The kernel could fail to bring a CPU online if the
    hardware supported both, the acpi-cpufreq and
    intel_pstate modules. This update ensures that the
    acpi-cpufreq module is not loaded in the intel_pstate
    module is loaded.

  - Due to a bug in the time accounting of the kernel
    scheduler, a divide error could occur when hot adding a
    CPU. To fix this problem, the kernel scheduler time
    accounting has been reworked.

  - The kernel did not handle exceptions caused by an
    invalid floating point control (FPC) register, resulting
    in a kernel oops. This problem has been fixed by placing
    the label to handle these exceptions to the correct
    place in the code.

  - A previous change to the kernel for the PowerPC
    architecture changed implementation of the
    compat_sys_sendfile() function. Consequently, the 64-bit
    sendfile() system call stopped working for files larger
    than 2 GB on PowerPC. This update restores previous
    behavior of sendfile() on PowerPC, and it again process
    files bigger than 2 GB as expected.

  - Previously, the kernel scheduler could schedule a CPU
    topology update even though the topology did not change.
    This could negatively affect the CPU load balancing,
    cause degradation of the system performance, and
    eventually result in a kernel oops. This problem has
    been fixed by skipping the CPU topology update if the
    topology has not actually changed.

  - Previously, recovery of a double-degraded RAID6 array
    could, under certain circumstances, result in data
    corruption. This could happen because the md driver was
    using an optimization that is safe to use only for
    single-degraded arrays. This update ensures that this
    optimization is skipped during the recovery of
    double-degraded RAID6 arrays.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=460
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49635565"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-123.9.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-123.9.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
