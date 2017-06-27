#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88799);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/17 15:19:25 $");

  script_cve_id("CVE-2015-5157", "CVE-2015-7872");

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
"  - It was found that the Linux kernel's keys subsystem did
    not correctly garbage collect uninstantiated keyrings. A
    local attacker could use this flaw to crash the system
    or, potentially, escalate their privileges on the
    system. (CVE-2015-7872, Important)

  - A flaw was found in the way the Linux kernel handled
    IRET faults during the processing of NMIs. An
    unprivileged, local user could use this flaw to crash
    the system or, potentially (although highly unlikely),
    escalate their privileges on the system. (CVE-2015-5157,
    Moderate)

This update also fixes the following bugs :

  - Previously, processing packets with a lot of different
    IPv6 source addresses caused the kernel to return
    warnings concerning soft-lockups due to high lock
    contention and latency increase. With this update, lock
    contention is reduced by backing off concurrent waiting
    threads on the lock. As a result, the kernel no longer
    issues warnings in the described scenario.

  - Prior to this update, block device readahead was
    artificially limited. As a consequence, the read
    performance was poor, especially on RAID devices. Now,
    per-device readahead limits are used for each device
    instead of a global limit. As a result, read performance
    has improved, especially on RAID devices.

  - After injecting an EEH error, the host was previously
    not recovering and observing I/O hangs in HTX tool logs.
    This update makes sure that when one or both of
    EEH_STATE_MMIO_ACTIVE and EEH_STATE_MMIO_ENABLED flags
    is marked in the PE state, the PE's IO path is regarded
    as enabled as well. As a result, the host no longer
    hangs and recovers as expected.

  - The genwqe device driver was previously using the
    GFP_ATOMIC flag for allocating consecutive memory pages
    from the kernel's atomic memory pool, even in non-atomic
    situations. This could lead to allocation failures
    during memory pressure. With this update, the genwqe
    driver's memory allocations use the GFP_KERNEL flag, and
    the driver can allocate memory even during memory
    pressure situations.

  - The nx842 co-processor for IBM Power Systems could in
    some circumstances provide invalid data due to a data
    corruption bug during uncompression. With this update,
    all compression and uncompression calls to the nx842 co-
    processor contain a cyclic redundancy check (CRC) flag,
    which forces all compression and uncompression
    operations to check data integrity and prevents the
    co-processor from providing corrupted data.

  - A failed 'updatepp' operation on the little-endian
    variant of IBM Power Systems could previously cause a
    wrong hash value to be used for the next hash insert
    operation in the page table. This could result in a
    missing hash pte update or invalidate operation,
    potentially causing memory corruption. With this update,
    the hash value is always recalculated after a failed
    'updatepp' operation, avoiding memory corruption.

  - Large Receive Offload (LRO) flag disabling was not being
    propagated downwards from above devices in vlan and bond
    hierarchy, breaking the flow of traffic. This problem
    has been fixed and LRO flags now propagate correctly.

  - Due to rounding errors in the CPU frequency of the
    intel_pstate driver, the CPU frequency never reached the
    value requested by the user. A kernel patch has been
    applied to fix these rounding errors.

  - When running several containers (up to 100), reports of
    hung tasks were previously reported. This update fixes
    the AB-BA deadlock in the dm_destroy() function, and the
    hung reports no longer occur.

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1602&L=scientific-linux-errata&F=&S=&P=9094
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?130a24e1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.10.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
