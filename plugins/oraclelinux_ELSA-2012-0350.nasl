#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0350 and 
# Oracle Linux Security Advisory ELSA-2012-0350 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68491);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347", "CVE-2011-4594", "CVE-2011-4611", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0207");
  script_bugtraq_id(50366, 50370, 50663, 50811, 50984, 51081, 51172, 51343, 51380, 51389);
  script_osvdb_id(76639, 76641, 77092, 77626, 77985, 78225, 78226, 78264, 78621, 79838);
  script_xref(name:"RHSA", value:"2012:0350");

  script_name(english:"Oracle Linux 6 : kernel (ELSA-2012-0350)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0350 :

Updated kernel packages that fix various security issues and several
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A buffer overflow flaw was found in the way the Linux kernel's XFS
file system implementation handled links with overly long path names.
A local, unprivileged user could use this flaw to cause a denial of
service or escalate their privileges by mounting a specially crafted
disk. (CVE-2011-4077, Moderate)

* Flaws in ghash_update() and ghash_final() could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-4081,
Moderate)

* A flaw was found in the Linux kernel's Journaling Block Device
(JBD). A local, unprivileged user could use this flaw to crash the
system by mounting a specially crafted ext3 or ext4 disk.
(CVE-2011-4132, Moderate)

* It was found that the kvm_vm_ioctl_assign_device() function in the
KVM (Kernel-based Virtual Machine) subsystem of a Linux kernel did not
check if the user requesting device assignment was privileged or not.
A local, unprivileged user on the host could assign unused PCI
devices, or even devices that were in use and whose resources were not
properly claimed by the respective drivers, which could result in the
host crashing. (CVE-2011-4347, Moderate)

* Two flaws were found in the way the Linux kernel's __sys_sendmsg()
function, when invoked via the sendmmsg() system call, accessed
user-space memory. A local, unprivileged user could use these flaws to
cause a denial of service. (CVE-2011-4594, Moderate)

* The RHSA-2011:1530 kernel update introduced an integer overflow flaw
in the Linux kernel. On PowerPC systems, a local, unprivileged user
could use this flaw to cause a denial of service. (CVE-2011-4611,
Moderate)

* A flaw was found in the way the KVM subsystem of a Linux kernel
handled PIT (Programmable Interval Timer) IRQs (interrupt requests)
when there was no virtual interrupt controller set up. A local,
unprivileged user on the host could force this situation to occur,
resulting in the host crashing. (CVE-2011-4622, Moderate)

* A flaw was found in the way the Linux kernel's XFS file system
implementation handled on-disk Access Control Lists (ACLs). A local,
unprivileged user could use this flaw to cause a denial of service or
escalate their privileges by mounting a specially crafted disk.
(CVE-2012-0038, Moderate)

* A flaw was found in the way the Linux kernel's KVM hypervisor
implementation emulated the syscall instruction for 32-bit guests. An
unprivileged guest user could trigger this flaw to crash the guest.
(CVE-2012-0045, Moderate)

* A divide-by-zero flaw was found in the Linux kernel's
igmp_heard_query() function. An attacker able to send certain IGMP
(Internet Group Management Protocol) packets to a target system could
use this flaw to cause a denial of service. (CVE-2012-0207, Moderate)

Red Hat would like to thank Nick Bowler for reporting CVE-2011-4081;
Sasha Levin for reporting CVE-2011-4347; Tetsuo Handa for reporting
CVE-2011-4594; Maynard Johnson for reporting CVE-2011-4611; Wang Xi
for reporting CVE-2012-0038; Stephan Barwolf for reporting
CVE-2012-0045; and Simon McVittie for reporting CVE-2012-0207.
Upstream acknowledges Mathieu Desnoyers as the original reporter of
CVE-2011-4594.

This update also fixes several bugs. Documentation for these changes
will be available shortly from the Technical Notes document linked to
in the References section.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted in
the Technical Notes. The system must be rebooted for this update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-March/002693.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_exists(release:"EL6", rpm:"kernel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-2.6.32-220.7.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-2.6.32-220.7.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-debug-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-debug-devel-2.6.32-220.7.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-devel-2.6.32") && rpm_check(release:"EL6", reference:"kernel-devel-2.6.32-220.7.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-doc-2.6.32") && rpm_check(release:"EL6", reference:"kernel-doc-2.6.32-220.7.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-firmware-2.6.32") && rpm_check(release:"EL6", reference:"kernel-firmware-2.6.32-220.7.1.el6")) flag++;
if (rpm_exists(release:"EL6", rpm:"kernel-headers-2.6.32") && rpm_check(release:"EL6", reference:"kernel-headers-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"perf-2.6.32-220.7.1.el6")) flag++;
if (rpm_check(release:"EL6", reference:"python-perf-2.6.32-220.7.1.el6")) flag++;


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
