#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0185 and 
# CentOS Errata and Security Advisory 2016:0185 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88759);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/08/01 15:11:42 $");

  script_cve_id("CVE-2015-5157", "CVE-2015-7872");
  script_osvdb_id(125208, 129330);
  script_xref(name:"RHSA", value:"2016:0185");

  script_name(english:"CentOS 7 : kernel (CESA-2016:0185)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix two security issues and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* It was found that the Linux kernel's keys subsystem did not
correctly garbage collect uninstantiated keyrings. A local attacker
could use this flaw to crash the system or, potentially, escalate
their privileges on the system. (CVE-2015-7872, Important)

* A flaw was found in the way the Linux kernel handled IRET faults
during the processing of NMIs. An unprivileged, local user could use
this flaw to crash the system or, potentially (although highly
unlikely), escalate their privileges on the system. (CVE-2015-5157,
Moderate)

This update also fixes the following bugs :

* Previously, processing packets with a lot of different IPv6 source
addresses caused the kernel to return warnings concerning soft-lockups
due to high lock contention and latency increase. With this update,
lock contention is reduced by backing off concurrent waiting threads
on the lock. As a result, the kernel no longer issues warnings in the
described scenario. (BZ#1285370)

* Prior to this update, block device readahead was artificially
limited. As a consequence, the read performance was poor, especially
on RAID devices. Now, per-device readahead limits are used for each
device instead of a global limit. As a result, read performance has
improved, especially on RAID devices. (BZ#1287550)

* After injecting an EEH error, the host was previously not recovering
and observing I/O hangs in HTX tool logs. This update makes sure that
when one or both of EEH_STATE_MMIO_ACTIVE and EEH_STATE_MMIO_ENABLED
flags is marked in the PE state, the PE's IO path is regarded as
enabled as well. As a result, the host no longer hangs and recovers as
expected. (BZ#1289101)

* The genwqe device driver was previously using the GFP_ATOMIC flag
for allocating consecutive memory pages from the kernel's atomic
memory pool, even in non-atomic situations. This could lead to
allocation failures during memory pressure. With this update, the
genwqe driver's memory allocations use the GFP_KERNEL flag, and the
driver can allocate memory even during memory pressure situations.
(BZ#1289450)

* The nx842 co-processor for IBM Power Systems could in some
circumstances provide invalid data due to a data corruption bug during
uncompression. With this update, all compression and uncompression
calls to the nx842 co-processor contain a cyclic redundancy check
(CRC) flag, which forces all compression and uncompression operations
to check data integrity and prevents the co-processor from providing
corrupted data. (BZ#1289451)

* A failed 'updatepp' operation on the little-endian variant of IBM
Power Systems could previously cause a wrong hash value to be used for
the next hash insert operation in the page table. This could result in
a missing hash pte update or invalidate operation, potentially causing
memory corruption. With this update, the hash value is always
recalculated after a failed 'updatepp' operation, avoiding memory
corruption. (BZ#1289452)

* Large Receive Offload (LRO) flag disabling was not being propagated
downwards from above devices in vlan and bond hierarchy, breaking the
flow of traffic. This problem has been fixed and LRO flags now
propagate correctly. (BZ#1292072)

* Due to rounding errors in the CPU frequency of the intel_pstate
driver, the CPU frequency never reached the value requested by the
user. A kernel patch has been applied to fix these rounding errors.
(BZ#1296276)

* When running several containers (up to 100), reports of hung tasks
were previously reported. This update fixes the AB-BA deadlock in the
dm_destroy() function, and the hung reports no longer occur.
(BZ#1296566)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-February/021705.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5174232"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-327.10.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-327.10.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
