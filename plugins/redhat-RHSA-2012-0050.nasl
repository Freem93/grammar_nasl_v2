#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0050. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64020);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/05 16:04:20 $");

  script_cve_id("CVE-2012-0029");
  script_osvdb_id(78506);
  script_xref(name:"RHSA", value:"2012:0050");

  script_name(english:"RHEL 6 : qemu-kvm (RHSA-2012:0050)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix one security issue, one bug, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. qemu-kvm is the user-space
component for running virtual machines using KVM.

A heap overflow flaw was found in the way QEMU-KVM emulated the e1000
network interface card. A privileged guest user in a virtual machine
whose network interface is configured to use the e1000 emulated driver
could use this flaw to crash the host or, possibly, escalate their
privileges on the host. (CVE-2012-0029)

Red Hat would like to thank Nicolae Mogoreanu for reporting this
issue.

This update also fixes the following bug :

* qemu-kvm has a 'scsi' option, to be used, for example, with the
'-device' option: '-device virtio-blk-pci,drive=[drive
name],scsi=off'. Previously, however, it only masked the feature bit,
and did not reject SCSI commands if a malicious guest ignored the
feature bit and issued a request. This update corrects this issue. The
'scsi=off' option can be used to mitigate the virtualization aspect of
CVE-2011-4127 before the RHSA-2011:1849 kernel update is installed on
the host.

This mitigation is only required if you do not have the RHSA-2011:1849
kernel update installed on the host and you are using raw format
virtio disks backed by a partition or LVM volume.

If you run guests by invoking /usr/libexec/qemu-kvm directly, use the
'-global virtio-blk-pci.scsi=off' option to apply the mitigation. If
you are using libvirt, as recommended by Red Hat, and have the
RHBA-2012:0013 libvirt update installed, no manual action is required:
guests will automatically use 'scsi=off'. (BZ#767721)

Note: After installing the RHSA-2011:1849 kernel update, SCSI requests
issued by guests via the SG_IO IOCTL will not be passed to the
underlying block device when using raw format virtio disks backed by a
partition or LVM volume, even if 'scsi=on' is used.

As well, this update adds the following enhancement :

* Prior to this update, qemu-kvm was not built with RELRO or PIE
support. qemu-kvm is now built with full RELRO and PIE support as a
security enhancement. (BZ#767906)

All users of qemu-kvm should upgrade to these updated packages, which
correct these issues and add this enhancement. After installing this
update, shut down all running virtual machines. Once all virtual
machines have shut down, start them again for this update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/kb/docs/DOC-67874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHSA-2011-1849.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://rhn.redhat.com/errata/RHBA-2012-0013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0050.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0050";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.209.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.209.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-debuginfo-0.12.1.2-2.209.el6_2.4")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.209.el6_2.4")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-img / qemu-kvm / qemu-kvm-debuginfo / qemu-kvm-tools");
  }
}
