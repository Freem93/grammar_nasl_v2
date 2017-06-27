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
  script_id(65797);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-5634", "CVE-2012-6075", "CVE-2013-0153", "CVE-2013-0154");

  script_name(english:"SuSE 11.2 Security Update : Xen (SAT Patch Number 7492)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN has been updated to fix various bugs and security issues :

  - (XSA 36) To avoid an erratum in early hardware, the Xen
    AMD IOMMU code by default choose to use a single
    interrupt remapping table for the whole system. This
    sharing implied that any guest with a passed through PCI
    device that is bus mastering capable can inject
    interrupts into other guests, including domain 0. This
    has been disabled for AMD chipsets not capable of it.
    (CVE-2013-0153)

  - qemu: The e1000 had overflows under some conditions,
    potentially corrupting memory. (CVE-2012-6075)

  - (XSA 37) Hypervisor crash due to incorrect ASSERT (debug
    build only). (CVE-2013-0154)

  - (XSA-33) A VT-d interrupt remapping source validation
    flaw was fixed. Also the following bugs have been fixed
    :. (CVE-2012-5634)

  - xen hot plug attach/detach fails. (bnc#805094)

  - domain locking can prevent a live migration from
    completing. (bnc#802690)

  - no way to control live migrations. (bnc#797014)

  - fix logic error in stdiostream_progress

  - restore logging in xc_save

  - add options to control migration tunables

  - enabling xentrace crashes hypervisor. (bnc#806736)

  - Upstream patches from Jan
    26287-sched-credit-pick-idle.patch
    26501-VMX-simplify-CR0-update.patch
    26502-VMX-disable-SMEP-when-not-paging.patch
    26516-ACPI-parse-table-retval.patch (Replaces
    CVE-2013-0153-xsa36.patch)
    26517-AMD-IOMMU-clear-irtes.patch (Replaces
    CVE-2013-0153-xsa36.patch)
    26518-AMD-IOMMU-disable-if-SATA-combined-mode.patch
    (Replaces CVE-2013-0153-xsa36.patch)
    26519-AMD-IOMMU-perdev-intremap-default.patch (Replaces
    CVE-2013-0153-xsa36.patch) 26526-pvdrv-no-devinit.patch
    26531-AMD-IOMMU-IVHD-special-missing.patch (Replaces
    CVE-2013-0153-xsa36.patch)

  - Add $network to xend initscript dependencies.
    (bnc#798188)

  - Unable to dvd or cdrom-boot DomU after xen-tools update
    Fixed with update to Xen version 4.1.4. (bnc#799694)

  - L3: HP iLo Generate NMI function not working in XEN
    kernel. (bnc#800156)

  - Upstream patches from Jan
    26404-x86-forward-both-NMI-kinds.patch
    26427-x86-AMD-enable-WC+.patch

  - Xen VMs with more than 2 disks randomly fail to start.
    (bnc#793927)

  - Upstream patches from Jan
    26332-x86-compat-show-guest-stack-mfn.patch
    26333-x86-get_page_type-assert.patch (Replaces
    CVE-2013-0154-xsa37.patch)
    26340-VT-d-intremap-verify-legacy-bridge.patch (Replaces
    CVE-2012-5634-xsa33.patch)
    26370-libxc-x86-initial-mapping-fit.patch

  - Update to Xen 4.1.4 c/s 23432

  - Update xenpaging.guest-memusage.patch add rule for
    xenmem to avoid spurious build failures

  - Upstream patches from Jan 26179-PCI-find-next-cap.patch
    26183-x86-HPET-masking.patch
    26188-x86-time-scale-asm.patch
    26200-IOMMU-debug-verbose.patch
    26203-x86-HAP-dirty-vram-leak.patch
    26229-gnttab-version-switch.patch (Replaces
    CVE-2012-5510-xsa26.patch)
    26230-x86-HVM-limit-batches.patch (Replaces
    CVE-2012-5511-xsa27.patch)
    26231-memory-exchange-checks.patch (Replaces
    CVE-2012-5513-xsa29.patch)
    26232-x86-mark-PoD-error-path.patch (Replaces
    CVE-2012-5514-xsa30.patch)
    26233-memop-order-checks.patch (Replaces
    CVE-2012-5515-xsa31.patch)
    26235-IOMMU-ATS-max-queue-depth.patch
    26272-x86-EFI-makefile-cflags-filter.patch
    26294-x86-AMD-Fam15-way-access-filter.patch
    CVE-2013-0154-xsa37.patch

  - Restore c/s 25751 in 23614-x86_64-EFI-boot.patch. Modify
    the EFI Makefile to do additional filtering."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5514.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0153.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0154.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7492.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-libs-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"xen-tools-domU-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-default-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-pae-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-kmp-trace-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-libs-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"xen-tools-domU-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-html-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-doc-pdf-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.4_02_3.0.58_0.6.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-libs-32bit-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-4.1.4_02-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-tools-domU-4.1.4_02-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
