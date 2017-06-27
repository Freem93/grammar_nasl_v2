#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(66985);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/07/26 00:30:55 $");

  script_cve_id("CVE-2013-1917", "CVE-2013-1918", "CVE-2013-1919", "CVE-2013-1920", "CVE-2013-1952", "CVE-2013-1964", "CVE-2013-2072", "CVE-2013-2076", "CVE-2013-2077", "CVE-2013-2078");

  script_name(english:"SuSE 11.2 Security Update : Xen (SAT Patch Number 7798)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN has been updated to 4.1.5 c/s 23509 to fix various bugs and
security issues.

The following security issues have been fixed :

  - Certain page table manipulation operations in Xen 4.1.x,
    4.2.x, and earlier were not preemptible, which allowed
    local PV kernels to cause a denial of service via
    vectors related to deep page table traversal.
    (CVE-2013-1918)

  - Xen 4.x, when using Intel VT-d for a bus mastering
    capable PCI device, did not properly check the source
    when accessing a bridge devices interrupt remapping
    table entries for MSI interrupts, which allowed local
    guest domains to cause a denial of service (interrupt
    injection) via unspecified vectors. (CVE-2013-1952)

  - A information leak in the XSAVE/XRSTOR instructions
    could be used to determine state of floating point
    operations in other domains. (CVE-2013-2076)

  - A denial of service (hypervisor crash) was possible due
    to missing exception recovery on XRSTOR, that could be
    used to crash the machine by PV guest users.
    (CVE-2013-2077)

  - A denial of service (hypervisor crash) was possible due
    to missing exception recovery on XSETBV, that could be
    used to crash the machine by PV guest users.
    (CVE-2013-2078)

  - Systems which allow untrusted administrators to
    configure guest vcpu affinity may be exploited to
    trigger a buffer overrun and corrupt memory.
    (CVE-2013-2072)

  - Xen 3.1 through 4.x, when running 64-bit hosts on Intel
    CPUs, did not clear the NT flag when using an IRET after
    a SYSENTER instruction, which allowed PV guest users to
    cause a denial of service (hypervisor crash) by
    triggering a #GP fault, which is not properly handled by
    another IRET instruction. (CVE-2013-1917)

  - Xen 4.2.x and 4.1.x did not properly restrict access to
    IRQs, which allowed local stub domain clients to gain
    access to IRQs and cause a denial of service via vectors
    related to 'passed-through IRQs or PCI devices.'.
    (CVE-2013-1919)

  - Xen 4.2.x, 4.1.x, and earlier, when the hypervisor is
    running 'under memory pressure' and the Xen Security
    Module (XSM) is enabled, used the wrong ordering of
    operations when extending the per-domain event channel
    tracking table, which caused a use-after-free and
    allowed local guest kernels to inject arbitrary events
    and gain privileges via unspecified vectors.
    (CVE-2013-1920)

  - Xen 4.0.x and 4.1.x incorrectly released a grant
    reference when releasing a non-v1, non-transitive grant,
    which allowed local guest administrators to cause a
    denial of service (host crash), obtain sensitive
    information, or possible have other impacts via
    unspecified vectors. (CVE-2013-1964)

Bugfixes :

  - Upstream patches from Jan
    26956-x86-mm-preemptible-cleanup.patch
    27071-x86-IO-APIC-fix-guest-RTE-write-corner-cases.patch
    27072-x86-shadow-fix-off-by-one-in-MMIO-permission-check
    .patch 27079-fix-XSA-46-regression-with-xend-xm.patch
    27083-AMD-iommu-SR56x0-Erratum-64-Reset-all-head-tail-po
    inters.patch

  - Update to Xen 4.1.5 c/s 23509 There were many xen.spec
    file patches dropped as now being included in the 4.1.5
    tarball.

  - can't use pv-grub to start domU (pygrub does work)
    xen.spec. (bnc#809662)

  - Upstream patches from Jan
    26702-powernow-add-fixups-for-AMD-P-state-figures.patch
    26704-x86-MCA-suppress-bank-clearing-for-certain-injecte
    d-events.patch
    26731-AMD-IOMMU-Process-softirqs-while-building-dom0-iom
    mu-mappings.patch
    26733-VT-d-Enumerate-IOMMUs-when-listing-capabilities.pa
    tch
    26734-ACPI-ERST-Name-table-in-otherwise-opaque-error-mes
    sages.patch
    26736-ACPI-APEI-Unlock-apei_iomaps_lock-on-error-path.pa
    tch 26737-ACPI-APEI-Add-apei_exec_run_optional.patch
    26742-IOMMU-properly-check-whether-interrupt-remapping-i
    s-enabled.patch
    26743-VT-d-deal-with-5500-5520-X58-errata.patch
    26744-AMD-IOMMU-allow-disabling-only-interrupt-remapping
    .patch
    26749-x86-reserve-pages-when-SandyBridge-integrated-grap
    hics.patch
    26765-hvm-Clean-up-vlapic_reg_write-error-propagation.pa
    tch
    26770-x86-irq_move_cleanup_interrupt-must-ignore-legacy-
    vectors.patch
    26771-x86-S3-Restore-broken-vcpu-affinity-on-resume.patc
    h
    26772-VMX-Always-disable-SMEP-when-guest-is-in-non-pagin
    g-mode.patch
    26773-x86-mm-shadow-spurious-warning-when-unmapping-xenh
    eap-pages.patch
    26799-x86-don-t-pass-negative-time-to-gtime_to_gtsc.patc
    h
    26851-iommu-crash-Interrupt-remapping-is-also-disabled-o
    n-crash.patch

  - Unable to create XEN virtual machines in SLED 11 SP2 on
    Kyoto xend-cpuinfo-model-name.patch. (bnc#814709)

  - Upstream patches from Jan 26536-xenoprof-div-by-0.patch
    26578-AMD-IOMMU-replace-BUG_ON.patch
    26656-x86-fix-null-pointer-dereference-in-intel_get_exte
    nded_msrs.patch
    26659-AMD-IOMMU-erratum-746-workaround.patch
    26660-x86-fix-CMCI-injection.patch
    26672-vmx-fix-handling-of-NMI-VMEXIT.patch
    26673-Avoid-stale-pointer-when-moving-domain-to-another-
    cpupool.patch
    26676-fix-compat-memory-exchange-op-splitting.patch
    26677-x86-make-certain-memory-sub-ops-return-valid-value
    s.patch 26678-SEDF-avoid-gathering-vCPU-s-on-pCPU0.patch
    26679-x86-defer-processing-events-on-the-NMI-exit-path.p
    atch
    26683-credit1-Use-atomic-bit-operations-for-the-flags-st
    ructure.patch
    26692-x86-MSI-fully-protect-MSI-X-table.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809662"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1917.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1919.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1920.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1952.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1964.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2078.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7798.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-libs-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-tools-domU-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-libs-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-tools-domU-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.5_02_3.0.74_0.6.10-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.5_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.5_02-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
