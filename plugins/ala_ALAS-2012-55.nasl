#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2012-55.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69662);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/30 14:43:53 $");

  script_cve_id("CVE-2011-4077", "CVE-2011-4081", "CVE-2011-4132", "CVE-2011-4347", "CVE-2011-4594", "CVE-2011-4611", "CVE-2011-4622", "CVE-2012-0038", "CVE-2012-0045", "CVE-2012-0207");
  script_xref(name:"ALAS", value:"2012-55");
  script_xref(name:"RHSA", value:"2012:0350");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2012-55)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow flaw was found in the way the Linux kernel's XFS
file system implementation handled links with overly long path names.
A local, unprivileged user could use this flaw to cause a denial of
service or escalate their privileges by mounting a specially crafted
disk. (CVE-2011-4077 , Moderate)

Flaws in ghash_update() and ghash_final() could allow a local,
unprivileged user to cause a denial of service. (CVE-2011-4081 ,
Moderate)

A flaw was found in the Linux kernel's Journaling Block Device (JBD).
A local, unprivileged user could use this flaw to crash the system by
mounting a specially crafted ext3 or ext4 disk. (CVE-2011-4132 ,
Moderate)

It was found that the kvm_vm_ioctl_assign_device() function in the KVM
(Kernel-based Virtual Machine) subsystem of a Linux kernel did not
check if the user requesting device assignment was privileged or not.
A local, unprivileged user on the host could assign unused PCI
devices, or even devices that were in use and whose resources were not
properly claimed by the respective drivers, which could result in the
host crashing. (CVE-2011-4347 , Moderate)

Two flaws were found in the way the Linux kernel's __sys_sendmsg()
function, when invoked via the sendmmsg() system call, accessed
user-space memory. A local, unprivileged user could use these flaws to
cause a denial of service. (CVE-2011-4594 , Moderate)

A previous update introduced an integer overflow flaw in the Linux
kernel. On PowerPC systems, a local, unprivileged user could use this
flaw to cause a denial of service. (CVE-2011-4611 , Moderate)

A flaw was found in the way the KVM subsystem of a Linux kernel
handled PIT (Programmable Interval Timer) IRQs (interrupt requests)
when there was no virtual interrupt controller set up. A local,
unprivileged user on the host could force this situation to occur,
resulting in the host crashing. (CVE-2011-4622 , Moderate)

A flaw was found in the way the Linux kernel's XFS file system
implementation handled on-disk Access Control Lists (ACLs). A local,
unprivileged user could use this flaw to cause a denial of service or
escalate their privileges by mounting a specially crafted disk.
(CVE-2012-0038 , Moderate)

A flaw was found in the way the Linux kernel's KVM hypervisor
implementation emulated the syscall instruction for 32-bit guests. An
unprivileged guest user could trigger this flaw to crash the guest.
(CVE-2012-0045 , Moderate)

A divide-by-zero flaw was found in the Linux kernel's
igmp_heard_query() function. An attacker able to send certain IGMP
(Internet Group Management Protocol) packets to a target system could
use this flaw to cause a denial of service. (CVE-2012-0207 , Moderate)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2012-55.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Run 'yum update kernel' to update your system. You will need to reboot
your system in order for the new kernel to be running."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-2.6.35.14-107.1.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-2.6.35.14-107.1.39.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.35.14-107.1.39.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.35.14-107.1.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-2.6.35.14-107.1.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-2.6.35.14-107.1.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-2.6.35.14-107.1.39.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-2.6.35.14-107.1.39.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
