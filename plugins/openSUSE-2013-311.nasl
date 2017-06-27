#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-311.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74967);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-5634", "CVE-2012-6075", "CVE-2013-0153", "CVE-2013-0154");
  script_osvdb_id(88127, 88128, 88130, 88131, 88655, 88913, 89058, 89319, 89867);

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2013:0637-1)");
  script_summary(english:"Check for the openSUSE-2013-311 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN was updated to fix various bugs and security issues :

Security issues fixed :

  - bnc#800275 - CVE-2013-0153: xen: interrupt remap entries
    shared and old ones not cleared on AMD IOMMUs

  - bnc#797523 - CVE-2012-6075: qemu / kvm-qemu: e1000
    overflows under some conditions

  - bnc#797031 - Xen Security Advisory 37 (CVE-2013-0154) -
    Hypervisor crash due to incorrect ASSERT (debug build
    only)

  - bnc#794316 - CVE-2012-5634: xen: VT-d interrupt
    remapping source validation flaw (XSA-33)

Bugs fixed :

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
    26692-x86-MSI-fully-protect-MSI-X-table.patch

  - bnc#805094 - xen hot plug attach/detach fails modified
    blktap-pv-cdrom.patch

  - bnc#802690 - domain locking can prevent a live migration
    from completing modified xend-domain-lock.patch

  - bnc#797014 - no way to control live migrations
    26547-tools-xc_fix_logic_error_in_stdiostream_progress.p
    atch
    26548-tools-xc_handle_tty_output_differently_in_stdiostr
    eam_progress.patch
    26549-tools-xc_turn_XCFLAGS__into_shifts.patch
    26550-tools-xc_restore_logging_in_xc_save.patch
    26551-tools-xc_log_pid_in_xc_save-xc_restore_output.patc
    h
    26675-tools-xentoollog_update_tty_detection_in_stdiostre
    am_progress.patch
    xen.migrate.tools-xc_print_messages_from_xc_save_with_xc
    _report.patch
    xen.migrate.tools-xc_document_printf_calls_in_xc_restore
    .patch
    xen.migrate.tools-xc_rework_xc_save.cswitch_qemu_logdirt
    y.patch
    xen.migrate.tools_set_migration_constraints_from_cmdline
    .patch
    xen.migrate.tools_add_xm_migrate_--log_progress_option.p
    atch

  - remove old patches: xen.xc.progress.patch
    xen.xc_save.details.patch
    xen.migration.abort_if_busy.patch

  - bnc#806736: enabling xentrace crashes hypervisor
    26686-xentrace_fix_off-by-one_in_calculate_tbuf_size.pat
    ch

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

  - bnc#798188 - Add $network to xend initscript
    dependencies

  - bnc#797014 - no way to control live migrations

  - fix logic error in stdiostream_progress
    xen.xc.progress.patch

  - restore logging in xc_save xen.xc_save.details.patch

  - add options to control migration tunables

    --max_iters, --max_factor, --abort_if_busy
    xen.migration.abort_if_busy.patch

  - bnc#799694 - Unable to dvd or cdrom-boot DomU after
    xen-tools update Fixed with update to Xen version 4.1.4

  - bnc#800156 - L3: HP iLo Generate NMI function not
    working in XEN kernel 26440-x86-forward-SERR.patch

  - Upstream patches from Jan
    26404-x86-forward-both-NMI-kinds.patch
    26427-x86-AMD-enable-WC+.patch 

  - bnc#793927 - Xen VMs with more than 2 disks randomly
    fail to start 25590-hotplug-locking.patch
    25595-hotplug-locking.patch 26079-hotplug-locking.patch

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
    the EFI Makefile to do additional filtering.
    EFI-makefile-cflags-filter.patch"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-04/msg00052.html"
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
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"xen-debugsource-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-devel-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-4.1.4_02_k3.4.33_2.24-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-debuginfo-4.1.4_02_k3.4.33_2.24-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-4.1.4_02_k3.4.33_2.24-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-debuginfo-4.1.4_02_k3.4.33_2.24-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-4.1.4_02_k3.4.33_2.24-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-debuginfo-4.1.4_02_k3.4.33_2.24-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-debuginfo-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-debuginfo-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-html-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-4.1.4_02-5.21.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.4_02-5.21.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
