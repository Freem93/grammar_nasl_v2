#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0088 and 
# CentOS Errata and Security Advisory 2010:0088 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44427);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 21:12:09 $");

  script_cve_id("CVE-2010-0297", "CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0309");
  script_osvdb_id(62112, 62215, 62347);
  script_xref(name:"RHSA", value:"2010:0088");

  script_name(english:"CentOS 5 : kvm (CESA-2010:0088)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix multiple security issues and several
bugs are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

The x86 emulator implementation was missing a check for the Current
Privilege Level (CPL) and I/O Privilege Level (IOPL). A user in a
guest could leverage these flaws to cause a denial of service (guest
crash) or possibly escalate their privileges within that guest.
(CVE-2010-0298, CVE-2010-0306)

A flaw was found in the Programmable Interval Timer (PIT) emulation.
Access to the internal data structure pit_state, which represents the
data state of the emulated PIT, was not properly validated in the
pit_ioport_read() function. A privileged guest user could use this
flaw to crash the host. (CVE-2010-0309)

A flaw was found in the USB passthrough handling code. A specially
crafted USB packet sent from inside a guest could be used to trigger a
buffer overflow in the usb_host_handle_control() function, which runs
under the QEMU-KVM context on the host. A user in a guest could
leverage this flaw to cause a denial of service (guest hang or crash)
or possibly escalate their privileges within the host. (CVE-2010-0297)

This update also fixes the following bugs :

* pvclock MSR values were not preserved during remote migration,
causing time drift for guests. (BZ#537028)

* SMBIOS table 4 data is now generated for Windows guests. (BZ#545874)

* if the qemu-kvm '-net user' option was used, unattended Windows XP
installations did not receive an IP address after reboot. (BZ#546562)

* when being restored from migration, a race condition caused Windows
Server 2008 R2 guests to hang during shutdown. (BZ#546563)

* the kernel symbol checking on the kvm-kmod build process has a
safety check for ABI changes. (BZ#547293)

* on hosts without high-res timers, Windows Server 2003 guests
experienced significant time drift. (BZ#547625)

* in some situations, installing Windows Server 2008 R2 from an ISO
image resulted in a blue screen 'BAD_POOL_HEADER' stop error.
(BZ#548368)

* a bug in the grow_refcount_table() error handling caused infinite
recursion in some cases. This caused the qemu-kvm process to hang and
eventually crash. (BZ#552159)

* for Windows Server 2003 R2, Service Pack 2, 32-bit guests, an
'unhandled vm exit' error could occur during reboot on some systems.
(BZ#552518)

* for Windows guests, QEMU could attempt to stop a stopped audio
device, resulting in a 'snd_playback_stop: ASSERT
playback_channel->base.active failed' error. (BZ#552519)

* the Hypercall driver did not reset the device on power-down.
(BZ#552528)

* mechanisms have been added to make older savevm versions to be
emitted in some cases. (BZ#552529)

* an error in the Makefile prevented users from using the source RPM
to install KVM. (BZ#552530)

* guests became unresponsive and could use up to 100% CPU when running
certain benchmark tests with more than 7 guests running
simultaneously. (BZ#553249)

* QEMU could terminate randomly with virtio-net and SMP enabled.
(BZ#561022)

All KVM users should upgrade to these updated packages, which contain
backported patches to resolve these issues. Note: The procedure in the
Solution section must be performed before this update will take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-February/016494.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e147500d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(16, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-105.el5_4.22")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-105.el5_4.22")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-105.el5_4.22")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-105.el5_4.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
