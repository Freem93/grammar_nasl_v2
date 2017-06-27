#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1281 and 
# CentOS Errata and Security Advisory 2014:1281 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77781);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/11/17 12:13:04 $");

  script_cve_id("CVE-2014-3917");
  script_bugtraq_id(67699);
  script_xref(name:"RHSA", value:"2014:1281");

  script_name(english:"CentOS 7 : kernel (CESA-2014:1281)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

* An out-of-bounds memory access flaw was found in the Linux kernel's
system call auditing implementation. On a system with existing audit
rules defined, a local, unprivileged user could use this flaw to leak
kernel memory to user space or, potentially, crash the system.
(CVE-2014-3917, Moderate)

This update also fixes the following bugs :

* A bug in the mtip32xx driver could prevent the Micron P420m PCIe SSD
devices with unaligned I/O access from completing the submitted I/O
requests. This resulted in a livelock situation and rendered the
Micron P420m PCIe SSD devices unusable. To fix this problem, mtip32xx
now checks whether an I/O access is unaligned and if so, it uses the
correct semaphore. (BZ#1125776)

* A series of patches has been backported to improve the functionality
of a touch pad on the latest Lenovo laptops in Red Hat Enterprise
Linux 7. (BZ#1122559)

* Due to a bug in the bnx2x driver, a network adapter could be unable
to recover from EEH error injection. The network adapter had to be
taken offline and rebooted in order to function properly again. With
this update, the bnx2x driver has been corrected and network adapters
now recover from EEH errors as expected. (BZ#1107722)

* Previously, if an hrtimer interrupt was delayed, all future pending
hrtimer events that were queued on the same processor were also
delayed until the initial hrtimer event was handled. This could cause
all hrtimer processing to stop for a significant period of time. To
prevent this problem, the kernel has been modified to handle all
expired hrtimer events when handling the initially delayed hrtimer
event. (BZ#1113175)

* A previous change to the nouveau driver introduced a bit shift
error, which resulted in a wrong display resolution being set with
some models of NVIDIA controllers. With this update, the erroneous
code has been corrected, and the affected NVIDIA controllers can now
set the correct display resolution. (BZ#1114869)

* Due to a NULL pointer dereference bug in the be2net driver, the
system could experience a kernel oops and reboot when disabling a
network adapter after a permanent failure. This problem has been fixed
by introducing a flag to keep track of the setup state. The failing
adapter can now be disabled successfully without a kernel crash.
(BZ#1122558)

* Previously, the Huge Translation Lookaside Buffer (HugeTLB) allowed
access to huge pages access by default. However, huge pages may be
unsupported in some environments, such as a KVM guest on a PowerPC
architecture, and an attempt to access a huge page in memory would
result in a kernel oops. This update ensures that HugeTLB denies
access to huge pages if the huge pages are not supported on the
system. (BZ#1122115)

* If an NVMe device becomes ready but fails to create I/O queues, the
nvme driver creates a character device handle to manage such a device.
Previously, a character device could be created before a device
reference counter was initialized, which resulted in a kernel oops.
This problem has been fixed by calling the relevant initialization
function earlier in the code. (BZ#1119720)

* On some firmware versions of the BladeEngine 3 (BE3) controller,
interrupts remain disabled after a hardware reset. This was a problem
for all Emulex-based network adapters using such a BE3 controller
because these adapters would fail to recover from an EEH error if it
occurred. To resolve this problem, the be2net driver has been modified
to enable the interrupts in the eeh_resume handler explicitly.
(BZ#1121712)

All kernel users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The system
must be rebooted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26a7bf1d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-abi-whitelists-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-devel-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-doc-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-headers-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perf-3.10.0-123.8.1.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-perf-3.10.0-123.8.1.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
