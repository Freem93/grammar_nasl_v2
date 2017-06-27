#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0008.
#

include("compat.inc");

if (description)
{
  script_id(88171);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2013-6375", "CVE-2015-8339", "CVE-2015-8340", "CVE-2016-1570", "CVE-2016-1571");
  script_bugtraq_id(63830);
  script_osvdb_id(131284, 131285, 133503, 133504);

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2016-0008)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - VT-d: fix TLB flushing in dma_pte_clear_one From: Jan
    Beulich The TLB flush code was wrong since
    xen-4.1.3-25.el5.127.20 (commit:
    vtd-Refactor-iotlb-flush-code.patch), both ovm-3.2.9 and
    ovm-3.2.10 were affected. The third parameter of
    __intel_iommu_iotlb_flush is to indicate whether the to
    be flushed entry was a present one. A few lines before,
    we bailed if !dma_pte_present(*pte), so there's no need
    to check the flag here again - we can simply always pass
    TRUE here. This is CVE-2013-6375 / XSA-78. Suggested-by:
    Cheng Yueqiang 

    (cherry picked from commit
    85c72f9fe764ed96f5c149efcdd69ab7c18bfe3d)
    (CVE-2013-6375)

  - x86/VMX: prevent INVVPID failure due to non-canonical
    guest address While INVLPG (and on SVM INVLPGA) don't
    fault on non-canonical addresses, INVVPID fails (in the
    'individual address' case) when passed such an address.
    Since such intercepted INVLPG are effectively no-ops
    anyway, don't fix this in vmx_invlpg_intercept, but
    instead have paging_invlpg never return true in such a
    case. This is XSA-168. (CVE-2016-1571)

  - x86/mm: PV superpage handling lacks sanity checks
    MMUEXT_[,UN]MARK_SUPER fail to check the input MFN for
    validity before dereferencing pointers into the
    superpage frame table. get_superpage has a similar
    issue. This is XSA-167. (CVE-2016-1570)

  - xend/image: Don't throw VMException when using backend
    domains for disks. If we are using backend domains the
    disk image may not be accessible within the host
    (domain0). As such it is OK to continue on. The
    'addStoreEntries' in DevController.py already does the
    check to make sure that when the 'backend' configuration
    is used - that said domain exists. As such the only
    change we need to do is to exclude the disk image
    location if the domain is not dom0.

  - memory: fix XENMEM_exchange error handling assign_pages
    can fail due to the domain getting killed in parallel,
    which should not result in a hypervisor crash. Also
    delete a redundant put_gfn - all relevant paths leading
    to the 'fail' label already do this (and there are also
    paths where it was plain wrong). All of the put_gfn-s
    got introduced by 51032ca058 ('Modify naming of queries
    into the p2m'), including the otherwise unneeded
    initializer for k (with even a kind of misleading
    comment - the compiler warning could actually have
    served as a hint that the use is wrong). This is
    XSA-159.

    Based on xen.org's xsa159.patch Conflicts: OVM 3.2 does
    not have the change (51032ca058) that is backed out in
    xen/common/memory.c or the put_gfn in
    xen/common/memory.c

(CVE-2015-8339, CVE-2015-8340)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-January/000412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8414f351"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.209.9")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.209.9")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.209.9")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-devel / xen-tools");
}
