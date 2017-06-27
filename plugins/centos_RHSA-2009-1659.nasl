#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1659 and 
# CentOS Errata and Security Advisory 2009:1659 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43811);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/28 23:54:22 $");

  script_cve_id("CVE-2009-4031");
  script_xref(name:"RHSA", value:"2009:1659");

  script_name(english:"CentOS 5 : kvm (CESA-2009:1659)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix one security issue and several bugs are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

On x86 platforms, the do_insn_fetch() function did not limit the
amount of instruction bytes fetched per instruction. Users in guest
operating systems could leverage this flaw to cause large latencies on
SMP hosts that could lead to a local denial of service on the host
operating system. This update fixes this issue by imposing the
architecturally-defined 15 byte length limit for instructions.
(CVE-2009-4031)

This update also fixes the following bugs :

* performance problems occurred when using the qcow2 image format with
the qemu-kvm -drive 'cache=none' option (the default setting when not
specified otherwise). This could cause guest operating system
installations to take hours. With this update, performance patches
have been backported so that using the qcow2 image format with the
'cache=none' option no longer causes performance issues. (BZ#520693)

* when using the virtual vm8086 mode, bugs in the emulated hardware
task switching implementation may have, in some situations, caused
older guest operating systems to malfunction. (BZ#532031)

* Windows Server 2003 guests (32-bit) with more than 4GB of memory may
have crashed during reboot when using the default qemu-kvm CPU
settings. (BZ#532043)

* with Red Hat Enterprise Virtualization, guests continued to run
after encountering disk read errors. This could have led to their file
systems becoming corrupted (but not the host's), notably in
environments that use networked storage. With this update, the
qemu-kvm -drive 'werror=stop' option now applies not only to write
errors but also to read errors: When using this option, guests will
pause on disk read and write errors.

By default, guests managed by Red Hat Enterprise Virtualization use
the 'werror=stop' option. This option is not used by default for
guests managed by libvirt. (BZ#537334, BZ#540406)

* the para-virtualized block driver (virtio-blk) silently ignored read
errors when accessing disk images. With this update, the driver
correctly signals the read error to the guest. (BZ#537334)

All KVM users should upgrade to these updated packages, which contain
backported patches to resolve these issues. Note: The procedure in the
Solution section must be performed before this update will take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-December/016390.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3321b739"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-105.el5_4.13")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-105.el5_4.13")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-105.el5_4.13")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-105.el5_4.13")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
