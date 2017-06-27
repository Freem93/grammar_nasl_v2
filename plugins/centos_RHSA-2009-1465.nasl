#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1465 and 
# CentOS Errata and Security Advisory 2009:1465 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43796);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/30 13:45:13 $");

  script_cve_id("CVE-2009-3290");
  script_bugtraq_id(36512);
  script_osvdb_id(58214);
  script_xref(name:"RHSA", value:"2009:1465");

  script_name(english:"CentOS 5 : kvm (CESA-2009:1465)");
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

This update has been rated as having important security impact by the
Red Hat Security Response Team.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

The kvm_emulate_hypercall() implementation was missing a check for the
Current Privilege Level (CPL). A local, unprivileged user in a virtual
machine could use this flaw to cause a local denial of service or
escalate their privileges within that virtual machine. (CVE-2009-3290)

This update also fixes the following bugs :

* non-maskable interrupts (NMI) were not supported on systems with AMD
processors. As a consequence, Windows Server 2008 R2 guests running
with more than one virtual CPU assigned on systems with AMD processors
would hang at the Windows shut down screen when a restart was
attempted. This update adds support for NMI filtering on systems with
AMD processors, allowing clean restarts of Windows Server 2008 R2
guests running with multiple virtual CPUs. (BZ#520694)

* significant performance issues for guests running 64-bit editions of
Windows. This update improves performance for guests running 64-bit
editions of Windows. (BZ#521793)

* Windows guests may have experienced time drift. (BZ#521794)

* removing the Red Hat VirtIO Ethernet Adapter from a guest running
Windows Server 2008 R2 caused KVM to crash. With this update, device
removal should not cause this issue. (BZ#524557)

All KVM users should upgrade to these updated packages, which contain
backported patches to resolve these issues. Note: The procedure in the
Solution section must be performed before this update takes effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31428331"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kmod-kvm-83-105.el5_4.7")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-83-105.el5_4.7")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-qemu-img-83-105.el5_4.7")) flag++;
if (rpm_check(release:"CentOS-5", cpu:"x86_64", reference:"kvm-tools-83-105.el5_4.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
