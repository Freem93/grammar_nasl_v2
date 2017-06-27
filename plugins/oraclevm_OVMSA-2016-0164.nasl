#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0164.
#

include("compat.inc");

if (description)
{
  script_id(95278);
  script_version("$Revision: 3.12 $");
  script_cvs_date("$Date: 2017/02/17 16:18:34 $");

  script_cve_id("CVE-2016-7777", "CVE-2016-9379", "CVE-2016-9380", "CVE-2016-9382", "CVE-2016-9383", "CVE-2016-9385", "CVE-2016-9386");
  script_osvdb_id(145066, 147621, 147622, 147623, 147653, 147655, 147656);
  script_xref(name:"IAVB", value:"2016-B-0149");
  script_xref(name:"IAVB", value:"2016-B-0177");

  script_name(english:"OracleVM 3.4 : xen (OVMSA-2016-0164)");
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

  - BUILDINFO:
    commit=5e4dc2c5fbd14b065234c0b5e5b637e0e005fab7

  - pygrub: Properly quote results, when returning them to
    the caller: (Ian Jackson) [Orabug: 25094263]
    (CVE-2016-9379) (CVE-2016-9380)

  - x86emul: fix huge bit offset handling (Jan Beulich)
    [Orabug: 25088366] (CVE-2016-9383)

  - x86/PV: writes of %fs and %gs base MSRs require
    canonical addresses (Jan Beulich) [Orabug: 25087576]
    (CVE-2016-9385)

  - x86/HVM: don't load LDTR with VM86 mode attrs during
    task switch (Jan Beulich) [Orabug: 25087539]
    (CVE-2016-9382)

  - x86/hvm: Fix the handling of non-present segments
    (Andrew Cooper) [Orabug: 25087515] (CVE-2016-9386)

  - BUILDINFO:
    commit=286bb9711e33d92767e8608bea4d3da6dbeeb710

  - move TLB-flush filtering out into populate_physmap
    during vm creation (Dongli Zhang) [Orabug: 24951888]

  - replace tlbflush check and operation with inline
    functions (Dongli Zhang) [Orabug: 24951888]

  - x86/hvm: extend HVM cpuid leaf with vcpu id (Paul
    Durrant) - x86/hvm: add HVM-specific hypervisor CPUID
    leaf (Boris Ostrovsky) - xend: soft_reset support.
    (Konrad Rzeszutek Wilk) - (lib)xl: soft reset support
    (Vitaly Kuznetsov) - tools/libxl: Save and restore
    EMULATOR_XENSTORE_DATA content (Andrew Cooper) - libxl:
    introduce libxl__device_model_xs_path (Wei Liu) - libxl:
    add LIBXL_DEVICE_MODEL_SAVE_FILE (Vitaly Kuznetsov) -
    libxc: support XEN_DOMCTL_soft_reset operation (Vitaly
    Kuznetsov) - arch-specific hooks for domain_soft_reset
    (Vitaly Kuznetsov) - flask: DOMCTL_soft_reset support
    (Vitaly Kuznetsov) - introduce XEN_DOMCTL_soft_reset
    (Vitaly Kuznetsov) - evtchn: make evtchn_reset ready for
    soft reset (Vitaly Kuznetsov) - evtchn: make
    EVTCHNOP_reset suitable for kexec (Vitaly Kuznetsov) -
    xl: introduce enum domain_restart_type (Vitaly
    Kuznetsov) - libxl: support SHUTDOWN_soft_reset shutdown
    reason (Vitaly Kuznetsov) - introduce
    SHUTDOWN_soft_reset shutdown reason (Vitaly Kuznetsov) -
    x86emul: honor guest CR0.TS and CR0.EM (Jan Beulich)
    [Orabug: 24697001] (CVE-2016-7777)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2016-November/000589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?07deecef"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/23");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (! ereg(pattern:"^OVS" + "3\.4" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.4", reference:"xen-4.4.4-105.0.2.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"xen-tools-4.4.4-105.0.2.el6")) flag++;

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
