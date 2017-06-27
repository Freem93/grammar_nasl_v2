#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61315);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2012-1601", "CVE-2012-2121");

  script_name(english:"Scientific Linux Security Update : kvm on SL5.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KVM (Kernel-based Virtual Machine) is a full virtualization solution
for Linux on AMD64 and Intel 64 systems. KVM is a Linux kernel module
built for the standard Scientific Linux kernel.

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

  - An off-by-one error in the QEMU guest's memory
    management could, in rare cases, cause QEMU-KVM to crash
    due to a segmentation fault in
    tb_invalidate_phys_page_range() if a device initiated
    DMA into a specific guest address. In a reported case,
    this issue presented on a system that had a guest using
    the 8139cp network driver.

All users of kvm are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Note that
the procedure in the Solution section must be performed before this
update will take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1205&L=scientific-linux-errata&T=0&P=1264
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6636ae38"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-83-249.el5_8.4")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-debug-83-249.el5_8.4")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-83-249.el5_8.4")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-debuginfo-83-249.el5_8.4")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-qemu-img-83-249.el5_8.4")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-tools-83-249.el5_8.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
