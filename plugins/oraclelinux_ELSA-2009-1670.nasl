#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1670 and 
# Oracle Linux Security Advisory ELSA-2009-1670 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67972);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/07 20:57:51 $");

  script_cve_id("CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726");
  script_bugtraq_id(36723, 36824, 36827, 36936);
  script_osvdb_id(59210, 59211, 59222, 59877);
  script_xref(name:"RHSA", value:"2009:1670");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2009-1670)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1670 :

Updated kernel packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fixes :

* NULL pointer dereference flaws in the r128 driver. Checks to test if
the Concurrent Command Engine state was initialized were missing in
private IOCTL functions. An attacker could use these flaws to cause a
local denial of service or escalate their privileges. (CVE-2009-3620,
Important)

* a NULL pointer dereference flaw in the NFSv4 implementation. Several
NFSv4 file locking functions failed to check whether a file had been
opened on the server before performing locking operations on it. A
local user on a system with an NFSv4 share mounted could possibly use
this flaw to cause a denial of service or escalate their privileges.
(CVE-2009-3726, Important)

* a flaw in tcf_fill_node(). A certain data structure in this function
was not initialized properly before being copied to user-space. This
could lead to an information leak. (CVE-2009-3612, Moderate)

* unix_stream_connect() did not check if a UNIX domain socket was in
the shutdown state. This could lead to a deadlock. A local,
unprivileged user could use this flaw to cause a denial of service.
(CVE-2009-3621, Moderate)

Knowledgebase DOC-20536 has steps to mitigate NULL pointer dereference
flaws.

Bug fixes :

* frequently changing a CPU between online and offline caused a kernel
panic on some systems. (BZ#545583)

* for the LSI Logic LSI53C1030 Ultra320 SCSI controller, read commands
sent could receive incorrect data, preventing correct data transfer.
(BZ#529308)

* pciehp could not detect PCI Express hot plug slots on some systems.
(BZ#530383)

* soft lockups: inotify race and contention on dcache_lock.
(BZ#533822, BZ#537019)

* priority ordered lists are now used for threads waiting for a given
mutex. (BZ#533858)

* a deadlock in DLM could cause GFS2 file systems to lock up.
(BZ#533859)

* use-after-free bug in the audit subsystem crashed certain systems
when running usermod. (BZ#533861)

* on certain hardware configurations, a kernel panic when the Broadcom
iSCSI offload driver (bnx2i.ko and cnic.ko) was loaded. (BZ#537014)

* qla2xxx: Enabled MSI-X, and correctly handle the module parameter to
control it. This improves performance for certain systems. (BZ#537020)

* system crash when reading the cpuaffinity file on a system.
(BZ#537346)

* suspend-resume problems on systems with lots of logical CPUs, e.g.
BX-EX. (BZ#539674)

* off-by-one error in the legacy PCI bus check. (BZ#539675)

* TSC was not made available on systems with multi-clustered APICs.
This could cause slow performance for time-sensitive applications.
(BZ#539676)

* ACPI: ARB_DISABLE now disabled on platforms that do not need it.
(BZ#539677)

* fix node to core and power-aware scheduling issues, and a kernel
panic during boot on certain AMD Opteron processors. (BZ#539678,
BZ#540469, BZ#539680, BZ#539682)

* APIC timer interrupt issues on some AMD Opteron systems prevented
achieving full power savings. (BZ#539681)

* general OProfile support for some newer Intel processors.
(BZ#539683)

* system crash during boot when NUMA is enabled on systems using MC
and kernel-xen. (BZ#539684)

* on some larger systems, performance issues due to a spinlock.
(BZ#539685)

* APIC errors when IOMMU is enabled on some AMD Opteron systems.
(BZ#539687)

* on some AMD Opteron systems, repeatedly taking a CPU offline then
online caused a system hang. (BZ#539688)

* I/O page fault errors on some systems. (BZ#539689)

* certain memory configurations could cause the kernel-xen kernel to
fail to boot on some AMD Opteron systems. (BZ#539690)

* NMI watchdog is now disabled for offline CPUs. (BZ#539691)

* duplicate directories in /proc/acpi/processor/ on BX-EX systems.
(BZ#539692)

* links did not come up when using bnx2x with certain Broadcom
devices. (BZ#540381)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-December/001284.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL5", rpm:"kernel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-PAE-devel-2.6.18") && rpm_check(release:"EL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-debug-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-debug-devel-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-devel-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-doc-2.6.18") && rpm_check(release:"EL5", reference:"kernel-doc-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-headers-2.6.18") && rpm_check(release:"EL5", reference:"kernel-headers-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-2.6.18-164.9.1.0.1.el5")) flag++;
if (rpm_exists(release:"EL5", rpm:"kernel-xen-devel-2.6.18") && rpm_check(release:"EL5", reference:"kernel-xen-devel-2.6.18-164.9.1.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
