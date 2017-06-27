#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1849 and 
# CentOS Errata and Security Advisory 2011:1849 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(57404);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/28 23:58:54 $");

  script_cve_id("CVE-2011-4127", "CVE-2011-4621");
  script_osvdb_id(78014);
  script_xref(name:"RHSA", value:"2011:1849");

  script_name(english:"CentOS 6 : kernel (CESA-2011:1849)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and various bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

Security fix :

* Using the SG_IO IOCTL to issue SCSI requests to partitions or LVM
volumes resulted in the requests being passed to the underlying block
device. If a privileged user only had access to a single partition or
LVM volume, they could use this flaw to bypass those restrictions and
gain read and write access (and be able to issue other SCSI commands)
to the entire block device.

In KVM (Kernel-based Virtual Machine) environments using raw format
virtio disks backed by a partition or LVM volume, a privileged guest
user could bypass intended restrictions and issue read and write
requests (and other SCSI commands) on the host, and possibly access
the data of other guests that reside on the same underlying block
device. Partition-based and LVM-based storage pools are not used by
default. Refer to Red Hat Bugzilla bug 752375 for further details and
a mitigation script for users who cannot apply this update
immediately. (CVE-2011-4127, Important)

Bug fixes :

* Previously, idle load balancer kick requests from other CPUs could
be serviced without first receiving an inter-processor interrupt
(IPI). This could have led to a deadlock. (BZ#750459)

* This update fixes a performance regression that may have caused
processes (including KVM guests) to hang for a number of seconds.
(BZ#751403)

* When md_raid1_unplug_device() was called while holding a spinlock,
under certain device failure conditions, it was possible for the lock
to be requested again, deeper in the call chain, causing a deadlock.
Now, md_raid1_unplug_device() is no longer called while holding a
spinlock. (BZ#755545)

* In hpet_next_event(), an interrupt could have occurred between the
read and write of the HPET (High Performance Event Timer) and the
value of HPET_COUNTER was then beyond that being written to the
comparator (HPET_Tn_CMP). Consequently, the timers were overdue for up
to several minutes. Now, a comparison is performed between the value
of the counter and the comparator in the HPET code. If the counter is
beyond the comparator, the '-ETIME' error code is returned.
(BZ#756426)

* Index allocation in the virtio-blk module was based on a
monotonically increasing variable 'index'. Consequently, released
indexes were not reused and after a period of time, no new were
available. Now, virtio-blk uses the ida API to allocate indexes.
(BZ#756427)

* A bug related to Context Caching existed in the Intel IOMMU support
module. On some newer Intel systems, the Context Cache mode has
changed from previous hardware versions, potentially exposing a
Context coherency race. The bug was exposed when performing a series
of hot plug and unplug operations of a Virtual Function network device
which was immediately configured into the network stack, i.e.,
successfully performed dynamic host configuration protocol (DHCP).
When the coherency race occurred, the assigned device would not work
properly in the guest virtual machine. With this update, the Context
coherency is corrected and the race and potentially resulting device
assignment failure no longer occurs. (BZ#757671)

* The align_va_addr kernel parameter was ignored if secondary CPUs
were initialized. This happened because the parameter settings were
overridden during the initialization of secondary CPUs. Also, the
align_va_addr parameter documentation contained incorrect parameter
arguments. With this update, the underlying code has been modified to
prevent the overriding and the documentation has been updated. This
update also removes the unused code introduced by the patch for
BZ#739456. (BZ#758028)

* Dell systems based on a future Intel processor with graphics
acceleration required the selection of the install system with basic
video driver installation option. This update removes this
requirement. (BZ#758513)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-December/018358.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75fe3f1e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"kernel-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-debug-devel-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-devel-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-doc-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-firmware-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kernel-headers-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"perf-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-perf-2.6.32-220.2.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
