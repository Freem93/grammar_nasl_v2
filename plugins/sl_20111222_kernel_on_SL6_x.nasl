#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61212);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-4127");

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

Security fix :

  - Using the SG_IO IOCTL to issue SCSI requests to
    partitions or LVM volumes resulted in the requests being
    passed to the underlying block device. If a privileged
    user only had access to a single partition or LVM
    volume, they could use this flaw to bypass those
    restrictions and gain read and write access (and be able
    to issue other SCSI commands) to the entire block
    device.

In KVM (Kernel-based Virtual Machine) environments using raw format
virtio disks backed by a partition or LVM volume, a privileged guest
user could bypass intended restrictions and issue read and write
requests (and other SCSI commands) on the host, and possibly access
the data of other guests that reside on the same underlying block
device. Partition-based and LVM-based storage pools are not used by
default. (CVE-2011-4127, Important)

Bug fixes :

  - Previously, idle load balancer kick requests from other
    CPUs could be serviced without first receiving an
    inter-processor interrupt (IPI). This could have led to
    a deadlock.

  - This update fixes a performance regression that may have
    caused processes (including KVM guests) to hang for a
    number of seconds.

  - When md_raid1_unplug_device() was called while holding a
    spinlock, under certain device failure conditions, it
    was possible for the lock to be requested again, deeper
    in the call chain, causing a deadlock. Now,
    md_raid1_unplug_device() is no longer called while
    holding a spinlock.

  - In hpet_next_event(), an interrupt could have occurred
    between the read and write of the HPET (High Performance
    Event Timer) and the value of HPET_COUNTER was then
    beyond that being written to the comparator
    (HPET_Tn_CMP). Consequently, the timers were overdue for
    up to several minutes. Now, a comparison is performed
    between the value of the counter and the comparator in
    the HPET code. If the counter is beyond the comparator,
    the '-ETIME' error code is returned.

  - Index allocation in the virtio-blk module was based on a
    monotonically increasing variable 'index'. Consequently,
    released indexes were not reused and after a period of
    time, no new were available. Now, virtio-blk uses the
    ida API to allocate indexes.

  - A bug related to Context Caching existed in the Intel
    IOMMU support module. On some newer Intel systems, the
    Context Cache mode has changed from previous hardware
    versions, potentially exposing a Context coherency race.
    The bug was exposed when performing a series of hot plug
    and unplug operations of a Virtual Function network
    device which was immediately configured into the network
    stack, i.e., successfully performed dynamic host
    configuration protocol (DHCP). When the coherency race
    occurred, the assigned device would not work properly in
    the guest virtual machine. With this update, the Context
    coherency is corrected and the race and potentially
    resulting device assignment failure no longer occurs.

  - The align_va_addr kernel parameter was ignored if
    secondary CPUs were initialized. This happened because
    the parameter settings were overridden during the
    initialization of secondary CPUs. Also, the
    align_va_addr parameter documentation contained
    incorrect parameter arguments. With this update, the
    underlying code has been modified to prevent the
    overriding and the documentation has been updated.

  - Dell systems based on a future Intel processor with
    graphics acceleration required the selection of the
    install system with basic video driver installation
    option. This update removes this requirement."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=4306
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37025e11"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/22");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-220.2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-220.2.1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
