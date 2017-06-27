#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91215);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2016-0758");

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
"Security Fix(es) :

  - A flaw was found in the way the Linux kernel's ASN.1 DER
    decoder processed certain certificate files with tags of
    indefinite length. A local, unprivileged user could use
    a specially crafted X.509 certificate DER file to crash
    the system or, potentially, escalate their privileges on
    the system. (CVE-2016-0758, Important)

Bug Fix(es) :

  - Under certain conditions, the migration threads could
    race with the CPU hotplug, which could cause a deadlock.
    A set of patches has been provided to fix this bug, and
    the deadlock no longer occurs in the system.

  - A bug in the code that cleans up revoked delegations
    could previously cause a soft lockup in the NFS server.
    This patch fixes the underlying source code, so the
    lockup no longer occurs.

  - The second attempt to reload Common Application
    Programming Interface (CAPI) devices on the
    little-endian variant of IBM Power Systems previously
    failed. The provided set of patches fixes this bug, and
    reloading works as intended.

  - Due to inconsistencies in page size of IOMMU, the NVMe
    device, and the kernel, the BUG_ON signal previously
    occurred in the nvme_setup_prps() function, leading to
    the system crash while setting up the DMA transfer. The
    provided patch sets the default NVMe page size to 4k,
    thus preventing the system crash.

  - Previously, on a system using the Infiniband mlx5 driver
    used for the SRP stack, a hard lockup previously
    occurred after the kernel exceeded time with lock held
    with interrupts blocked. As a consequence, the system
    panicked. This update fixes this bug, and the system no
    longer panics in this situation.

  - On the little-endian variant of IBM Power Systems, the
    kernel previously crashed in the bitmap_weight()
    function while running the memory affinity script. The
    provided patch fortifies the topology setup and prevents
    sd->child from being set to NULL when it is already
    NULL. As a result, the memory affinity script runs
    successfully.

  - When a KVM guest wrote random values to the
    special-purpose registers (SPR) Instruction Authority
    Mask Register (IAMR), the guest and the corresponding
    QEMU process previously hung. This update adds the code
    which sets SPRs to a suitable neutral value on guest
    exit, thus fixing this bug.

  - Under heavy iSCSI traffic load, the system previously
    panicked due to a race in the locking code leading to a
    list corruption. This update fixes this bug, and the
    system no longer panics in this situation.

  - During SCSI exception handling (triggered by some
    irregularities), the driver could previously use an
    already retired SCSI command. As a consequence, a kernel
    panic or data corruption occurred. The provided patches
    fix this bug, and exception handling now proceeds
    successfully.

  - When the previously opened /dev/tty, which pointed to a
    pseudo terminal (pty) pair, was the last file closed, a
    kernel crash could previously occur. The underlying
    source code has been fixed, preventing this bug.

  - Previously, when using VPLEX and FCoE via the bnx2fc
    driver, different degrees of data corruption occurred.
    The provided patch fixes the FCP Response (RSP) residual
    parsing in bnx2fc, which prevents the aforementioned
    corruption."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1605&L=scientific-linux-errata&F=&S=&P=5024
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1286486c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-327.18.2.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-327.18.2.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
