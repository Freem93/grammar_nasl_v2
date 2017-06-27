#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0743. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74461);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:40:57 $");

  script_cve_id("CVE-2013-4148", "CVE-2013-4151", "CVE-2013-4535", "CVE-2013-4536", "CVE-2013-4541", "CVE-2013-4542", "CVE-2013-6399", "CVE-2014-0182", "CVE-2014-2894", "CVE-2014-3461");
  script_bugtraq_id(66932, 66976, 67392, 67394, 67483);
  script_xref(name:"RHSA", value:"2014:0743");

  script_name(english:"RHEL 6 : qemu-kvm (RHSA-2014:0743)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated qemu-kvm packages that fix multiple security issues and two
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. The qemu-kvm package provides
the user-space component for running virtual machines using KVM.

Multiple buffer overflow, input validation, and out-of-bounds write
flaws were found in the way the virtio, virtio-net, virtio-scsi, and
usb drivers of QEMU handled state loading after migration. A user able
to alter the savevm data (either on the disk or over the wire during
migration) could use either of these flaws to corrupt QEMU process
memory on the (destination) host, which could potentially result in
arbitrary code execution on the host with the privileges of the QEMU
process. (CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536,
CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182,
CVE-2014-3461)

An out-of-bounds memory access flaw was found in the way QEMU's IDE
device driver handled the execution of SMART EXECUTE OFFLINE commands.
A privileged guest user could use this flaw to corrupt QEMU process
memory on the host, which could potentially result in arbitrary code
execution on the host with the privileges of the QEMU process.
(CVE-2014-2894)

The CVE-2013-4148, CVE-2013-4151, CVE-2013-4535, CVE-2013-4536,
CVE-2013-4541, CVE-2013-4542, CVE-2013-6399, CVE-2014-0182, and
CVE-2014-3461 issues were discovered by Michael S. Tsirkin of Red Hat,
Anthony Liguori, and Michael Roth.

This update also fixes the following bugs :

* Previously, under certain circumstances, libvirt failed to start
guests which used a non-zero PCI domain and SR-IOV Virtual Functions
(VFs), and returned the following error message :

Can't assign device inside non-zero PCI segment as this KVM module
doesn't support it.

This update fixes this issue and guests using the aforementioned
configuration no longer fail to start. (BZ#1099941)

* Due to an incorrect initialization of the cpus_sts bitmap, which
holds the enablement status of a vCPU, libvirt could fail to start a
guest with an unusual vCPU topology (for example, a guest with three
cores and two sockets). With this update, the initialization of
cpus_sts has been corrected, and libvirt no longer fails to start the
aforementioned guests. (BZ#1100575)

All qemu-kvm users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing this update, shut down all running virtual machines. Once
all virtual machines have shut down, start them again for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4151.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4535.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4536.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6399.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-2894.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-3461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0743.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0743";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qemu-guest-agent-0.12.1.2-2.415.el6_5.10")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-guest-agent-0.12.1.2-2.415.el6_5.10")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-img-0.12.1.2-2.415.el6_5.10")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-0.12.1.2-2.415.el6_5.10")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"qemu-kvm-debuginfo-0.12.1.2-2.415.el6_5.10")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-debuginfo-0.12.1.2-2.415.el6_5.10")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"qemu-kvm-tools-0.12.1.2-2.415.el6_5.10")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-guest-agent / qemu-img / qemu-kvm / qemu-kvm-debuginfo / etc");
  }
}
