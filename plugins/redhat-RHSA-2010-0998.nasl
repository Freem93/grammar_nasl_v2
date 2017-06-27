#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0998. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63966);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/04 16:02:20 $");

  script_cve_id("CVE-2010-3881");
  script_bugtraq_id(44666);
  script_osvdb_id(69003);
  script_xref(name:"RHSA", value:"2010:0998");

  script_name(english:"RHEL 5 : kvm (RHSA-2010:0998)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kvm packages that fix one security issue and three bugs are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

It was found that some structure padding and reserved fields in
certain data structures in QEMU-KVM were not initialized properly
before being copied to user-space. A privileged host user with access
to '/dev/kvm' could use this flaw to leak kernel stack memory to
user-space. (CVE-2010-3881)

Red Hat would like to thank Vasiliy Kulikov for reporting this issue.

This update also fixes the following bugs :

* The 'kvm_amd' kernel module did not initialize the TSC (Time Stamp
Counter) offset in the VMCB (Virtual Machine Control Block) correctly.
After a vCPU (virtual CPU) has been created, the TSC offset in the
VMCB should have a negative value so that the virtual machine will see
TSC values starting at zero. However, the TSC offset was set to zero
and therefore the virtual machine saw the same TSC value as the host.
With this update, the TSC offset has been updated to show the correct
values. (BZ#656984)

* Setting the boot settings of a virtual machine to, firstly, boot
from PXE and, secondly, to boot from the hard drive would result in a
PXE boot loop, that is, the virtual machine would not continue to boot
from the hard drive if the PXE boot failed. This was caused by a flaw
in the 'bochs-bios' (part of KVM) code. With this update, after a
virtual machine tries to boot from PXE and fails, it continues to boot
from a hard drive if there is one present. (BZ#659850)

* If a 64-bit Red Hat Enterprise Linux 5.5 virtual machine was
migrated to another host with a different CPU clock speed, the clock
of that virtual machine would consistently lose or gain time
(approximately half a second for every second the host is running). On
machines that do not use the kvm clock, the network time protocol
daemon (ntpd) could correct the time drifts caused by migration.
However, using the pvclock caused the time to change consistently.
This was due to flaws in the save/load functions of pvclock. With this
update, the issue has been fixed and migrating a virtual machine no
longer causes time drift. (BZ#660239)

All KVM users should upgrade to these updated packages, which contain
backported patches to correct these issues. Note: The procedure in the
Solution section must be performed before this update will take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3881.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0998.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/20");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0998";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kmod-kvm-83-164.el5_5.30")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kvm-83-164.el5_5.30")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kvm-qemu-img-83-164.el5_5.30")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"kvm-tools-83-164.el5_5.30")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kvm / kvm-qemu-img / kvm-tools");
  }
}
