#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0074.
#

include("compat.inc");

if (description)
{
  script_id(79521);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_cve_id("CVE-2012-4544", "CVE-2013-1432", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-2194", "CVE-2013-2195", "CVE-2013-2196", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368");
  script_bugtraq_id(56289, 59292, 59615, 60701, 60702, 60703, 60799, 62708, 62710, 62935);

  script_name(english:"OracleVM 2.2 : xen (OVMSA-2013-0074)");
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

  - x86: check segment descriptor read result in 64-bit OUTS
    emulation XSA-67 (Matthew Daley) [orabug 17571640]
    (CVE-2013-4368)

  - x86: properly set up fbld emulation operand address
    XSA-66 (Jan Beulich) [orabug 17472492] (CVE-2013-4361)

  - x86: properly handle hvm_copy_from_guest_[phys,virt]
    errors XSA-63 (Jan Beulich) [orabug 17472461]
    (CVE-2013-4355)

  - libxc: builder: limit maximum size of kernel/ramdisk
    (Ian Campbell) [orabug 15852491] (CVE-2012-4544)

  - libxc: builder: Correct fix for CVE-2012-4544 (Ian
    Campbell) [orabug 15852491] (CVE-2012-4544)

  - [PATCH 01/21] libelf: abolish libelf-relocate.c (Ian
    Jackson) [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - [PATCH 02/21] libxc: introduce xc_dom_seg_to_ptr_pages
    (Ian Jackson) [orabug 16902308] (CVE-2013-2194
    CVE-2013-2195 CVE-2013-2196)

  - [PATCH 03/21] libxc: Fix range checking in
    xc_dom_pfn_to_ptr etc. (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 04/21] libelf: abolish elf_sval and
    elf_access_signed (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 05/21] libelf/xc_dom_load_elf_symtab: Do not use
    'syms' uninitialised (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 06/21] libelf: introduce macros for memory access
    and pointer handling (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 07/21] tools/xcutils/readnotes: adjust
    print_l1_mfn_valid_note (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 08/21] libelf: check nul-terminated strings
    properly (Ian Jackson) [orabug 16902308] (CVE-2013-2194
    CVE-2013-2195 CVE-2013-2196)

  - [PATCH 09/21] libelf: check all pointer accesses (Ian
    Jackson) [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - [PATCH 10/21] libelf: Check pointer references in
    elf_is_elfbinary (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 11/21] libelf: Make all callers call
    elf_check_broken (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 12/21] libelf: use C99 bool for booleans (Ian
    Jackson) [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - [PATCH 13/21] libelf: use only unsigned integers (Ian
    Jackson) [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - [PATCH 14/21] libxc: Introduce xc_bitops.h (Ian Jackson)
    [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - [PATCH 15/21] libelf: check loops for running away (Ian
    Jackson) [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - [PATCH 16/21] libelf: abolish obsolete macros (Ian
    Jackson) [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - [PATCH 17/21] libxc: Add range checking to
    xc_dom_binloader (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 18/21] libxc: check failure of xc_dom_*_to_ptr,
    xc_map_foreign_range (Ian Jackson) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - [PATCH 19/21] libxc: check return values from malloc
    (Ian Jackson) [orabug 16902308] (CVE-2013-2194
    CVE-2013-2195 CVE-2013-2196)

  - [PATCH 20/21] libxc: range checks in xc_dom_p2m_host and
    _guest (Ian Jackson) [orabug 16902308] (CVE-2013-2194
    CVE-2013-2195 CVE-2013-2196)

  - [PATCH 21/21] libxc: check blob size before proceeding
    in xc_dom_check_gzip (Matthew Daley) [orabug 16902308]
    (CVE-2013-2194 CVE-2013-2195 CVE-2013-2196)

  - libxc: define INVALID_MFN for the XSA-55 patchset (Chuck
    Anderson) [orabug 16902308] (CVE-2013-2194 CVE-2013-2195
    CVE-2013-2196)

  - fix page refcount handling in page table pin error path
    (Andrew Cooper) [orabug 16949882] (CVE-2013-1432)

  - remove CVE-2013-1919 (Chuck Anderson) [orabug 16635741]
    (CVE-2013-1919)

  - x86: make vcpu_destroy_pagetables preemptible (Jan
    Beulich) [orabug 16714903] (CVE-2013-1918)

  - x86: make new_guest_cr3 preemptible (Jan Beulich)
    [orabug 16714903] (CVE-2013-1918)

  - x86: make MMUEXT_NEW_USER_BASEPTR preemptible (Jan
    Beulich) [orabug 16714903] (CVE-2013-1918)

  - x86: make vcpu_reset preemptible (Jan Beulich) [orabug
    16714903] (CVE-2013-1918)

  - x86: make arch_set_info_guest preemptible (Jan Beulich)
    [orabug 16714903] (CVE-2013-1918)

  - x86: make page table unpinning preemptible (Jan Beulich)
    [orabug 16714903] (CVE-2013-1918)

  - x86: make page table handling error paths preemptible
    (Jan Beulich) [orabug 16714903] (CVE-2013-1918)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2013-October/000185.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82e75a28"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-pvhvm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"xen-3.4.0-0.1.55.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-64-3.4.0-0.1.55.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-debugger-3.4.0-0.1.55.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-devel-3.4.0-0.1.55.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-pvhvm-devel-3.4.0-0.1.55.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"xen-tools-3.4.0-0.1.55.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-64 / xen-debugger / xen-devel / xen-pvhvm-devel / etc");
}
