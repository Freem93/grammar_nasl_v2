#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0704. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76899);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2014-2894");
  script_bugtraq_id(66932);
  script_xref(name:"RHSA", value:"2014:0704");

  script_name(english:"RHEL 7 : qemu-kvm (RHSA-2014:0704)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm packages provide
a user-space component to run virtual machines using KVM.

An out-of-bounds memory access flaw was found in the way QEMU's IDE
device driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-2894)

This update also fixes the following bugs :

* Prior to this update, a bug in the migration code caused the
following error on specific machine types: after a Red Hat Enterprise
Linux 6.5 guest was migrated from a Red Hat Enterprise Linux 6.5 host
to a Red Hat Enterprise Linux 7.0 host and then restarted, the boot
failed and the guest automatically restarted. Thus, the guest entered
an endless loop. With this update, the migration code has been fixed
and the Red Hat Enterprise Linux 6.5 guests migrated in the
aforementioned scenario now boot properly. (BZ#1091322)

* Due to a regression bug in the iSCSI driver, the qemu-kvm process
terminated unexpectedly with a segmentation fault when the 'write
same' command was executed in guest mode under the iSCSI protocol.
This update fixes the regression and the 'write same' command now
functions in guest mode under iSCSI as intended. (BZ#1090978)

* Due to a mismatch in interrupt request (IRQ) routing, migration of a
Red Hat Enterprise Linux 6.5 guest from a Red Hat Enterprise Linux 6.5
host to a Red Hat Enterprise Linux 7.0 host could produce a call
trace. This happened if memory ballooning and a Universal Host Control
Interface (UHCI) device were used at the same time on certain machine
types. With this patch, the IRQ routing mismatch has been amended and
the described migration now proceeds as expected. (BZ#1090981)

* Previously, an internal error prevented KVM from executing a CPU hot
plug on a Red Hat Enterprise Linux 7 guest running on a Red Hat
Enterprise Linux 7 host. This update addresses the internal error and
CPU hot plugging in the described scenario now functions correctly.
(BZ#1094820)

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0704.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcacard-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0704";
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
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libcacard-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"libcacard-devel-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-devel-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"libcacard-tools-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-guest-agent-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-img-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-common-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"i686", reference:"qemu-kvm-debuginfo-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-debuginfo-1.5.3-60.el7_0.2")) flag++;
  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"qemu-kvm-tools-1.5.3-60.el7_0.2")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libcacard / libcacard-devel / libcacard-tools / qemu-guest-agent / etc");
  }
}
