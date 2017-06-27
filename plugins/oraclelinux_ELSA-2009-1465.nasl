#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1465 and 
# Oracle Linux Security Advisory ELSA-2009-1465 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67932);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:49:12 $");

  script_cve_id("CVE-2009-3290");
  script_bugtraq_id(36512);
  script_osvdb_id(58214);
  script_xref(name:"RHSA", value:"2009:1465");

  script_name(english:"Oracle Linux 5 : kvm (ELSA-2009-1465)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1465 :

Updated kvm packages that fix one security issue and several bugs are
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-September/001178.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kmod-kvm-83-105.0.1.el5_4.7")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-83-105.0.1.el5_4.7")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-qemu-img-83-105.0.1.el5_4.7")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-tools-83-105.0.1.el5_4.7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kvm / kvm-qemu-img / kvm-tools");
}
