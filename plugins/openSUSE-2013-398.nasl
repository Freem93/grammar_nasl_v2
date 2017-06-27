#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-398.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74985);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:13 $");

  script_cve_id("CVE-2013-0913", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2013:0923-1)");
  script_summary(english:"Check for the openSUSE-2013-398 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 12.3 kernel was updated to fix various security issues
and bugs :

  - config.conf: Disable armv7hl/u8500 until it builds again

  -
    patches.fixes/ocfs2-Fix-oops-in-ocfs2_fast_symlink_readp
    age: ocfs2: Fix oops in ocfs2_fast_symlink_readpage()
    code path

  - drm/nouveau: Fix typo in init_idx_addr_latched()
    (bnc#800686).

  - rtl28xxu: Add USB ID for MaxMedia HU394-T (bnc#812113).

  - rtl28xxu: Add USB IDs for Compro VideoMate U620F
    (bnc#812113).

  - Support Digivox Mini HD (rtl2832) (bnc#812113).

  - rtl28xxu: correct some device names (bnc#812113).

  - rtl28xxu: add Gigabyte U7300 DVB-T Dongle (bnc#812113).

  - rtl28xxu: [1b80:d3a8] ASUS My Cinema-U3100Mini Plus V2
    (bnc#812113).

  - rtl28xxu: add NOXON DAB/DAB+ USB dongle rev 2
    (bnc#812113).

  - drm: correctly restore mappings if drm_open fails
    (bnc#807850).

  - Drivers: hv: vmbus: Fix a bug in hv_need_to_signal()
    (bnc#811417).

  - svcrpc: fix rpc server shutdown races (bnc#802812).

  - Update patches to what was accepted upstream.

  - Refresh
    patches.arch/kvm-convert-msr_kvm_system_time-to-use-gfn_
    to_hva_cache_init.patch.

  - Refresh
    patches.arch/kvm-fix-for-buffer-overflow-in-handling-of-
    msr_kvm_system_time.patch.

  - KVM: Convert MSR_KVM_SYSTEM_TIME to use
    gfn_to_hva_cache_init (bnc#806980 CVE-2013-1797).

  - KVM: Fix bounds checking in ioapic indirect register
    read (bnc#806980 CVE-2013-1798).

  - KVM: Fix for buffer overflow in handling of
    MSR_KVM_SYSTEM_TIME (bnc#806980 CVE-2013-1796).

  - kabi/severities: Allow kvm abi changes - kvm modules are
    self consistent

  - loopdev: fix a deadlock (bnc#809748).

  - block: use i_size_write() in bd_set_size() (bnc#809748).

  - drm/i915: bounds check execbuffer relocation count
    (bnc#808829,CVE-2013-0913).

  - TTY: do not reset master's packet mode (bnc#809330).

  - Update patches.fixes/ext3-Fix-format-string-issues.patch
    (bnc#809155 CVE-2013-1848).

  - ext3: Fix format string issues (bnc#809155).

  - Drivers: hv: balloon: Do not request completion
    notification (fate#314663).

  - e1000e: fix runtime power management transitions
    (bnc#806966).

  - e1000e: fix pci-device enable-counter balance
    (bnc#806966).

  - e1000e: fix accessing to suspended device (bnc#806966).

  - gpio-ich: Fix ichx_gpio_check_available() return what
    callers expect.

  - gpio/ich: Add missing spinlock init.

  - Refresh
    patches.suse/SUSE-bootsplash-mgadrmfb-workaround. Add
    the same w/a for ast and cirrus KMS, too (bnc#806990).

  - Fix broken VT1 output with mgadrmfb (bnc#806990).

  - PCI/PM: Clear state_saved during suspend (bnc#806966)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-06/msg00059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809330"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=811417"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812113"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/23");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-default-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-source-vanilla-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"kernel-syms-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-debugsource-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-3.7.10-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.7.10-1.4.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
