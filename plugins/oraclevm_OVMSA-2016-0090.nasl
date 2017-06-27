#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0090.
#

include("compat.inc");

if (description)
{
  script_id(92602);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2014-3672", "CVE-2016-3960", "CVE-2016-4480");
  script_osvdb_id(137353, 138720, 138952);

  script_name(english:"OracleVM 3.2 : xen (OVMSA-2016-0090)");
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

  - x86/HVM: correct CPUID leaf 80000008 handling - 6c733e54
    xsa173_01_0001-x86-HVM-correct-CPUID-leaf-80000008-handl
    ing.patch was based on upstream commit:
    ef437690af8b75e6758dce77af75a22b63982883 x86/HVM:
    correct CPUID leaf 80000008 handling It should have been
    based on upstream commit:
    6c733e549889a9b8c4e03140348b8e00241d4ce9 x86/HVM:
    correct CPUID leaf 80000008 handling The changes in this
    patch are the differences between those two patches.

  - x86/pv: Remove unsafe bits from the mod_l?_entry
    fastpath All changes in writeability and cacheability
    must go through full re-validation. Rework the logic as
    a whitelist, to make it clearer to follow. This is
    XSA-182

    Upstream commit 798c1498f764bfaa7b0b955bab40b01b0610d372
    Conflicts: xen/include/asm-x86/page.h

  - x86/mm: fully honor PS bits in guest page table walks In
    L4 entries it is currently unconditionally reserved (and
    hence should, when set, always result in a reserved bit
    page fault), and is reserved on hardware not supporting
    1Gb pages (and hence should, when set, similarly cause a
    reserved bit page fault on such hardware). This is
    CVE-2016-4480 / XSA-176. (CVE-2016-4480)

  - x86/mm: Handle 1GiB superpages in the pagetable walker.
    This allows HAP guests to use 1GiB superpages. Shadow
    and PV guests still can't use them without more support
    in shadow/* and mm.c.

    Conflicts: xen/arch/x86/hvm/hvm.c
    xen/arch/x86/mm/guest_walk.c Backported from upstream
    commit 96b740e209d0bea4c16d93211ceb139fc98d10c2
    (CVE-2016-4480)

  - main loop: Big hammer to fix logfile disk DoS in Xen
    setups Each time round the main loop, we now fstat
    stderr. If it is too big, we dup2 /dev/null onto it.
    This is not a very pretty patch but it is very simple,
    easy to see that it's correct, and has a low risk of
    collateral damage. The limit is 1Mby by default but can
    be adjusted by setting a new environment variable. This
    fixes CVE-2014-3672. (CVE-2014-3672)

  - x86: make hvm_cpuid tolerate NULL pointers Now that
    other HVM code started making more extensive use of
    hvm_cpuid, let's not force every caller to declare dummy
    variables for output not cared about.

    xen/arch/x86/hvm/svm/svm.c and
    xen/arch/x86/hvm/vmx/vvmx.c part are removed as no
    source matched. Upstream commit
    11b85dbd0ab068bad3beadda3aee2298205a3c01

  - x86: limit GFNs to 32 bits for shadowed superpages.
    Superpage shadows store the shadowed GFN in the
    backpointer field, which for non-BIGMEM builds is 32
    bits wide. Shadowing a superpage mapping of a
    guest-physical address above 2^44 would lead to the GFN
    being truncated there, and a crash when we come to
    remove the shadow from the hash table. Track the valid
    width of a GFN for each guest, including reporting it
    through CPUID, and enforce it in the shadow pagetables.
    Set the maximum witth to 32 for guests where this
    truncation could occur. This is XSA-173.

    Conflicts: xen/arch/x86/cpu/common.c
    arch/x86/mm/guest_walk.c Upstream commit
    95dd1b6e87b61222fc856724a5d828c9bdc30c80 (CVE-2016-3960)

  - x86/HVM: correct CPUID leaf 80000008 handling
    CPUID[80000008].EAX[23:16] have been given the meaning
    of the guest physical address restriction (in case it
    needs to be smaller than the host's), hence we need to
    mirror that into vCPUID[80000008].EAX[7:0]. Enforce a
    lower limit at the same time, as well as a fixed value
    for the virtual address bits, and zero for the guest
    physical address ones. In order for the vMTRR code to
    see these overrides we need to make it call hvm_cpuid
    instead of domain_cpuid, which in turn requires special
    casing (and relaxing) the controlling domain. This
    additionally should hide an ordering problem in the
    tools: Both xend and xl appear to be restoring a guest
    from its image before setting up the CPUID policy in the
    hypervisor, resulting in domain_cpuid returning all
    zeros and hence the check in mtrr_var_range_msr_set
    failing if the guest previously had more than the
    minimum 36 physical address bits.

    Conflicts: xen/arch/x86/hvm/mtrr.c Upstream commit
    ef437690af8b75e6758dce77af75a22b63982883 (CVE-2016-3960)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-July/000505.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-devel / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/28");
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
if (rpm_check(release:"OVS3.2", reference:"xen-4.1.3-25.el5.223.34")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-devel-4.1.3-25.el5.223.34")) flag++;
if (rpm_check(release:"OVS3.2", reference:"xen-tools-4.1.3-25.el5.223.34")) flag++;

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
