#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1042. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64044);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2011-4347", "CVE-2012-0038", "CVE-2012-0044", "CVE-2012-1097", "CVE-2012-1179");
  script_bugtraq_id(50811, 51371, 51380, 52274, 52533);
  script_osvdb_id(77626, 78226, 78227, 80123, 80605);
  script_xref(name:"RHSA", value:"2012:1042");

  script_name(english:"RHEL 6 : kernel (RHSA-2012:1042)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix various security issues and three
bugs are now available for Red Hat Enterprise Linux 6.1 Extended
Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

* A local, unprivileged user could use an integer overflow flaw in
drm_mode_dirtyfb_ioctl() to cause a denial of service or escalate
their privileges. (CVE-2012-0044, Important)

* It was found that the kvm_vm_ioctl_assign_device() function in the
KVM (Kernel-based Virtual Machine) subsystem of a Linux kernel did not
check if the user requesting device assignment was privileged or not.
A local, unprivileged user on the host could assign unused PCI
devices, or even devices that were in use and whose resources were not
properly claimed by the respective drivers, which could result in the
host crashing. (CVE-2011-4347, Moderate)

* A flaw was found in the way the Linux kernel's XFS file system
implementation handled on-disk Access Control Lists (ACLs). A local,
unprivileged user could use this flaw to cause a denial of service or
escalate their privileges by mounting a specially crafted disk.
(CVE-2012-0038, Moderate)

* It was found that the Linux kernel's register set (regset) common
infrastructure implementation did not check if the required get and
set handlers were initialized. A local, unprivileged user could use
this flaw to cause a denial of service by performing a register set
operation with a ptrace() PTRACE_SETREGSET or PTRACE_GETREGSET
request. (CVE-2012-1097, Moderate)

* A race condition was found in the Linux kernel's memory management
subsystem in the way pmd_none_or_clear_bad(), when called with
mmap_sem in read mode, and Transparent Huge Pages (THP) page faults
interacted. A privileged user in a KVM guest with the ballooning
functionality enabled could potentially use this flaw to crash the
host. A local, unprivileged user could use this flaw to crash the
system. (CVE-2012-1179, Moderate)

Red Hat would like to thank Chen Haogang for reporting CVE-2012-0044;
Sasha Levin for reporting CVE-2011-4347; Wang Xi for reporting
CVE-2012-0038; and H. Peter Anvin for reporting CVE-2012-1097.

This update also fixes the following bugs :

* When a RoCE (RDMA over Converged Ethernet) adapter with active RoCE
communications was taken down suddenly (either by adapter failure or
the intentional shutdown of the interface), the ongoing RoCE
communications could cause the kernel to panic and render the machine
unusable. A patch has been provided to protect the kernel in this
situation and to pass an error up to the application still using the
interface after it has been taken down instead. (BZ#799944)

* The fix for Red Hat Bugzilla bug 713494, released via
RHSA-2011:0928, introduced a regression. Attempting to change the
state of certain features, such as GRO (Generic Receive Offload) or
TSO (TCP segment offloading), for a 10 Gigabit Ethernet card that is
being used in a virtual LAN (VLAN) resulted in a kernel panic.
(BZ#816974)

* If a new file was created on a Network File System version 4 (NFSv4)
share, the ownership was set to nfsnobody (-2) until it was possible
to upcall to the idmapper. As a consequence, subsequent file system
operations could incorrectly use '-2' for the user and group IDs for
the given file, causing certain operations to fail. In reported cases,
this issue also caused 'Viminfo file is not writable' errors for users
running Vim with files on an NFSv4 share. (BZ#820960)

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The system must be
rebooted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-4347.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2011-0928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1042.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-s390x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1042";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-debug-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-debug-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-debug-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-debug-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-debug-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-debug-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-debug-devel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-debug-devel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-debug-devel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-debuginfo-common-i686-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-debuginfo-common-s390x-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-devel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-devel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-devel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", reference:"kernel-doc-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", reference:"kernel-firmware-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"kernel-headers-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-headers-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"kernel-headers-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-kdump-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-kdump-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"kernel-kdump-devel-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"perf-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"perf-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"perf-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"i686", reference:"perf-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"s390x", reference:"perf-debuginfo-2.6.32-131.29.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", sp:"1", cpu:"x86_64", reference:"perf-debuginfo-2.6.32-131.29.1.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
  }
}
