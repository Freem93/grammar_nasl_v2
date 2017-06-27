#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0676 and 
# Oracle Linux Security Advisory ELSA-2012-0676 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68527);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 17:07:15 $");

  script_cve_id("CVE-2012-1601", "CVE-2012-2121");
  script_bugtraq_id(53162, 53488);
  script_xref(name:"RHSA", value:"2012:0676");

  script_name(english:"Oracle Linux 5 : kvm (ELSA-2012-0676)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0676 :

Updated kvm packages that fix two security issues and one bug are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Red Hat Enterprise Linux kernel.

A flaw was found in the way the KVM_CREATE_IRQCHIP ioctl was handled.
Calling this ioctl when at least one virtual CPU (VCPU) already
existed could lead to a NULL pointer dereference later when the VCPU
is scheduled to run. A malicious user in the kvm group on the host
could use this flaw to crash the host. (CVE-2012-1601)

A flaw was found in the way device memory was handled during guest
device removal. Upon successful device removal, memory used by the
device was not properly unmapped from the corresponding IOMMU or
properly released from the kernel, leading to a memory leak. A
malicious user in the kvm group on the host who has the ability to
assign a device to a guest could use this flaw to crash the host.
(CVE-2012-2121)

This update also fixes the following bug :

* An off-by-one error in the QEMU guest's memory management could, in
rare cases, cause QEMU-KVM to crash due to a segmentation fault in
tb_invalidate_phys_page_range() if a device initiated DMA into a
specific guest address. In a reported case, this issue presented on a
system that had a guest using the 8139cp network driver. (BZ#816207)

All users of kvm are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Note that
the procedure in the Solution section must be performed before this
update will take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-May/002827.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kvm packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kmod-kvm-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/22");
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
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kmod-kvm-83-249.0.1.el5_8.4")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kmod-kvm-debug-83-249.0.1.el5_8.4")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-83-249.0.1.el5_8.4")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-qemu-img-83-249.0.1.el5_8.4")) flag++;
if (rpm_check(release:"EL5", cpu:"x86_64", reference:"kvm-tools-83-249.0.1.el5_8.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kmod-kvm-debug / kvm / kvm-qemu-img / kvm-tools");
}
