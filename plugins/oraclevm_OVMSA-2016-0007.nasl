#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0007.
#

include("compat.inc");

if (description)
{
  script_id(88170);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-5307", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8341", "CVE-2015-8554", "CVE-2015-8555", "CVE-2016-1570", "CVE-2016-1571");
  script_osvdb_id(130089, 130090, 131284, 131285, 131453, 132032, 132050, 133503, 133504);

  script_name(english:"OracleVM 3.3 : xen (OVMSA-2016-0007)");
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

  - x86/HVM: avoid reading ioreq state more than once
    Otherwise, especially when the compiler chooses to
    translate the switch to a jump table, unpredictable
    behavior (and in the jump table case arbitrary code
    execution) can result. This is XSA-166.

  - x86: don't leak ST(n)/XMMn values to domains first using
    them FNINIT doesn't alter these registers, and hence
    using it is insufficient to initialize a guest's initial
    state. This is XSA-165. (CVE-2015-8555)

  - MSI-X: avoid array overrun upon MSI-X table writes
    pt_msix_init allocates msix->msix_entry[] to just cover
    msix->total_entries entries. While pci_msix_readl
    resorts to reading physical memory for out of bounds
    reads, pci_msix_writel so far simply accessed/corrupted
    unrelated memory. pt_iomem_map's call to
    cpu_register_physical_memory registers a page granular
    region, which is necessary as the Pending Bit Array may
    share space with the MSI-X table (but nothing else is
    allowed to). This also explains why pci_msix_readl
    actually honors out of bounds reads, but pci_msi_writel
    doesn't need to. This is XSA-164. (CVE-2015-8554)

  - From 43a10fecd6f4a9d8adf9f5d85e3d5e7187e2d54a Mon Sep 17
    00:00:00 2001 From: Ian Jackson Date: Wed, 18 Nov 2015
    15:34:54 +0000 Subject: [PATCH] libxl: Fix
    bootloader-related virtual memory leak on pv build
    failure The bootloader may call
    libxl__file_reference_map, which mmap's the pv_kernel
    and pv_ramdisk into process memory. This was only
    unmapped, however, on the success path of
    libxl__build_pv. If there were a failure anywhere
    between libxl_bootloader.c:parse_bootloader_result and
    the end of libxl__build_pv, the calls to
    libxl__file_reference_unmap would be skipped, leaking
    the mapped virtual memory. Ideally this would be fixed
    by adding the unmap calls to the destruction path for
    libxl__domain_build_state. Unfortunately the lifetime of
    the libxl__domain_build_state is opaque, and it doesn't
    have a proper destruction path. But, the only thing in
    it that isn't from the gc are these bootloader
    references, and they are only ever set for one
    libxl__domain_build_state, the one which is
    libxl__domain_create_state.build_state. So we can clean
    up in the exit path from libxl__domain_create_*, which
    always comes through domcreate_complete. Remove the
    now-redundant unmaps in libxl__build_pv's success path.
    This is XSA-160.

    Based on xen.org's xsa160.patch Conflicts: adjust patch
    context to match OVM 3.3 code base (CVE-2015-8341)

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

22326022] (CVE-2015-8339, CVE-2015-8340)

  - x86/HVM: always intercept #AC and #DB Both being benign
    exceptions, and both being possible to get triggered by
    exception delivery, this is required to prevent a guest
    from locking up a CPU (resulting from no other VM exits
    occurring once getting into such a loop). The specific
    scenarios: 1) #AC may be raised during exception
    delivery if the handler is set to be a ring-3 one by a
    32-bit guest, and the stack is misaligned. 2) #DB may be
    raised during exception delivery when a breakpoint got
    placed on a data structure involved in delivering the
    exception. This can result in an endless loop when a
    64-bit guest uses a non-zero IST for the vector 1 IDT
    entry, but even without use of IST the time it takes
    until a contributory fault would get raised (results
    depending on the handler) may be quite long. This is
    XSA-156.

(CVE-2015-5307, CVE-2015-8104)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-January/000411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca4defaf"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

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
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"xen-4.3.0-55.el6.47.70")) flag++;
if (rpm_check(release:"OVS3.3", reference:"xen-tools-4.3.0-55.el6.47.70")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
