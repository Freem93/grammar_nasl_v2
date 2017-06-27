#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-375.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75363);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/11/16 15:47:33 $");

  script_cve_id("CVE-2013-4579", "CVE-2013-6885", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2013-7281", "CVE-2014-0069", "CVE-2014-0101", "CVE-2014-0196", "CVE-2014-1438", "CVE-2014-1446", "CVE-2014-1690", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1874", "CVE-2014-2523", "CVE-2014-2672");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2014:0678-1)");
  script_summary(english:"Check for the openSUSE-2014-375 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel security update fixes various security issues and
bugs.

The Linux Kernel was updated to fix various security issues and bugs.

Main security issues fixed :

A security issue in the tty layer that was fixed that could be used by
local attackers for code execution (CVE-2014-0196).

Two security issues in the floppy driver were fixed that could be used
by local attackers on machines with the floppy to crash the kernel or
potentially execute code in the kernel (CVE-2014-1737 CVE-2014-1738).

Other security issues and bugfixes :

  - netfilter: nf_nat: fix access to uninitialized buffer in
    IRC NAT helper (bnc#860835 CVE-2014-1690).

  - net: sctp: fix sctp_sf_do_5_1D_ce to verify if we/peer
    is AUTH (bnc#866102, CVE-2014-0101).

  - [media] ivtv: Fix Oops when no firmware is loaded
    (bnc#875440).

  - ALSA: hda - Add dock pin setups for Thinkpad T440
    (bnc#876699).

  - ip6tnl: fix double free of fb_tnl_dev on exit
    (bnc#876531).

  - Update arm config files: Enable all USB-to-serial
    drivers Specifically, enable USB_SERIAL_WISHBONE and
    USB_SERIAL_QT2 on all arm flavors.

  - mei: limit the number of consecutive resets
    (bnc#821619,bnc#852656).

  - mei: revamp mei reset state machine
    (bnc#821619,bnc#852656).

  - mei: use hbm idle state to prevent spurious resets
    (bnc#821619).

  - mei: do not run reset flow from the interrupt thread
    (bnc#821619,bnc#852656).

  - mei: don't get stuck in select during reset
    (bnc#821619).

  - mei: wake also writers on reset (bnc#821619).

  - mei: remove flash_work_queue (bnc#821619,bnc#852656).

  - mei: me: do not load the driver if the FW doesn't
    support MEI interface (bnc#821619).

  - Update ec2 config files: Disable CONFIG_CAN CAN support
    is disabled everywhere else, so disable it in ec2 too.

  - Refresh Xen patches (bnc#851244).

  - Update arm/exynos config file: disable AHCI_IMX This
    driver is only used on Freescale i.MX systems so it
    isn't needed on Exynos.

  - drm: Prefer noninterlace cmdline mode unless explicitly
    specified (bnc#853350).

  - kabi/severities: add exception for irda. The changes
    resulted in a 4x performance increase. Any external
    users of this API will also want to rebuild their
    modules.

  - i7core_edac: Fix PCI device reference count.

  - KABI: revert tcp: TSO packets automatic sizing.

  - KABI: revert tcp: TSQ can use a dynamic limit.

  - kabi: add exceptions for kvm and l2tp

  -
    patches.fixes/sunrpc-add-an-info-file-for-the-dummy-gssd
    -pipe.patch: Move include of utsname.h to where it's
    needed to avoid kABI breakage due to utsname becoming
    defined.

  - Update kabi files. The kABI references were never
    establishd at release.

  - Refresh patches.rpmify/chipidea-clean-up-dependencies
    Replace OF_DEVICE by OF (OF_DEVICE does not exist
    anymore.)

  - inet: fix addr_len/msg->msg_namelen assignment in
    recv_error and rxpmtu functions (bnc#857643
    CVE-2013-7263 CVE-2013-7264 CVE-2013-7265).

  - inet: prevent leakage of uninitialized memory to user in
    recv syscalls (bnc#857643 CVE-2013-7263 CVE-2013-7264
    CVE-2013-7265 CVE-2013-7281).

  - Update config files: re-enable twofish crypto support
    Software twofish crypto support was disabled in several
    architectures since openSUSE 10.3. For i386 and x86_64
    it was on purpose, because hardware-accelerated
    alternatives exist. However for all other architectures
    it was by accident. Re-enable software twofish crypto
    support in arm, ia64 and ppc configuration files, to
    guarantee that at least one implementation is always
    available (bnc#871325).

  - kvm: optimize away THP checks in kvm_is_mmio_pfn()
    (bnc#871160).

  - Update patches.fixes/mm-close-PageTail-race.patch
    (bnc#871160).

  - Update
    patches.fixes/mm-hugetlbfs-fix-hugetlbfs-optimization.pa
    tch (bnc#871160).

  - mm: close PageTail race (bnc#81660).

  - mm: hugetlbfs: fix hugetlbfs optimization (bnc#81660).

  - Update config files: disable CONFIG_TOUCHSCREEN_W90X900
    The w90p910_ts driver only makes sense on the W90x900
    architecture, which we do not support.

  - ath9k: protect tid->sched check
    (bnc#871148,CVE-2014-2672).

  - Update ec2 config files: disable CONFIG_INPUT_FF_MEMLESS
    This helper module is useless on EC2.

  - SELinux: Fix kernel BUG on empty security contexts
    (bnc#863335,CVE-2014-1874).

  - hamradio/yam: fix info leak in ioctl
    (bnc#858872,CVE-2014-1446).

  - netfilter: nf_conntrack_dccp: fix skb_header_pointer API
    usages (bnc#868653 CVE-2014-2523).

  - ath9k_htc: properly set MAC address and BSSID mask
    (bnc#851426,CVE-2013-4579).

  - drm/ttm: don't oops if no invalidate_caches()
    (bnc#869414).

  - Btrfs: do not bug_on if we try to cow a free space cache
    inode (bnc#863235).

  - Update vanilla config files: enable console rotation
    It's enabled in all other kernel flavors so it should be
    enabled in vanilla too.

  - Update config files. (CONFIG_EFIVAR_FS=m) Due to systemd
    can auto-load efivarfs.ko, so wet CONFIG_EFIVAR_FS to
    module on x86_64.

  - libata, freezer: avoid block device removal while system
    is frozen (bnc#849334).

  - Enable CONFIG_IRDA_FAST_RR=y (bnc#860502)

  - [media] bttv: don't setup the controls if there are no
    video devices (bnc#861750).

  - drm/i915/dp: add native aux defer retry limit
    (bnc#867718).

  - drm/i915/dp: increase native aux defer retry timeout
    (bnc#867718).

  - rpc_pipe: fix cleanup of dummy gssd directory when
    notification fails (bnc#862746).

  - sunrpc: add an 'info' file for the dummy gssd pipe
    (bnc#862746).

  - rpc_pipe: remove the clntXX dir if creating the pipe
    fails (bnc#862746).

  - Delete rpm/_constraints after mismerge

Sat Mar 8 00:41:07 CET 2014 - jbohac@suse.cz

  - Refresh
    patches.fixes/tcp-syncookies-reduce-cookie-lifetime-to-1
    28-seconds.patch.

  - tcp: syncookies: reduce cookie lifetime to 128 seconds
    (bnc#833968).

  - tcp: syncookies: reduce mss table to four values
    (bnc#833968).

  - rpm/mkspec: Generate a per-architecture per-package
    _constraints file

  - rpm/mkspec: Remove dead code

  - Refresh
    patches.fixes/rtc-cmos-add-an-alarm-disable-quirk.patch.

  - rtc-cmos: Add an alarm disable quirk (bnc#812592).

  - Refresh patches.xen/xen-x86-EFI.

  - Refresh
    patches.apparmor/apparmor-compatibility-patch-for-v5-net
    work-control.
    patches.drivers/pstore_disable_efi_backend_by_default.pa
    tch. patches.fixes/dm-table-switch-to-readonly.
    patches.fixes/kvm-ioapic.patch.
    patches.fixes/kvm-macos.patch.
    patches.fixes/remount-no-shrink-dcache.
    patches.fixes/scsi-dh-queuedata-accessors.
    patches.suse/0001-vfs-Hooks-for-more-fine-grained-direct
    ory-permission.patch.
    patches.suse/ovl01-vfs-add-i_op-dentry_open.patch.
    patches.suse/sd_init.mark_majors_busy.patch.

  - rpm/mkspec: Fix whitespace in NoSource lines

  - rpm/kernel-binary.spec.in: Do not zero modules.dep
    before using it (bnc#866075)

  - rpm/kernel-obs-build.spec: Drop useless ExclusiveArch
    statement

  - Update config files. Set CONFIG_EFIVAR_FS to build-in
    for MOK support Update config files. Set
    CONFIG_EFIVAR_FS to build-in for MOK support

  - nfs: always make sure page is up-to-date before
    extending a write to cover the entire page (bnc#864867
    bnc#865075).

  - x86, cpu, amd: Add workaround for family 16h, erratum
    793 (bnc#852967 CVE-2013-6885).

  - Refresh patches.xen/xen3-patch-3.10.

  - cifs: ensure that uncached writes handle unmapped areas
    correctly (bnc#864025 CVE-2014-0069).

  - x86, fpu, amd: Clear exceptions in AMD FXSAVE workaround
    (bnc#858638 CVE-2014-1438).

  - rpm/kernel-obs-build.spec: Do not mount /sys, the build
    script does it

  - Update config files: Disable TS5500-specific drivers
    These drivers are useless without TS5500 board support:
    mtd-ts5500, gpio-ts5500 and max197.

  - balloon: don't crash in HVM-with-PoD guests.

  - usbback: fix after c/s 1232:8806dfb939d4 (bnc#842553).

  - hwmon: (coretemp) Fix truncated name of alarm
    attributes.

  - rpm/kernel-obs-build.spec: Fix for ppc64le

  - Scripts: .nosrc.rpm should contain only the specfile
    (bnc #639379)

  - config: update arm7hl/exynos

  - Enhances exynos support :

  - Add USB support

  - Add sound support

  - Add devices (accelerometer, etc.) on arndale board

  - drm/cirrus: Fix cirrus drm driver for fbdev + qemu
    (bnc#856760).

  - Spec: zeroing modules.dep to get identical builds among
    different machines

  - doc/README.SUSE: Update to match the current package
    layout

  - Add the README.SUSE file to the packaging branch

  - lockd: send correct lock when granting a delayed lock
    (bnc#859342).

  - mm/page-writeback.c: do not count anon pages as
    dirtyable memory (reclaim stalls).

  - mm/page-writeback.c: fix dirty_balance_reserve
    subtraction from dirtyable memory (reclaim stalls)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00056.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=639379"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=81660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=821619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842553"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851426"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=869414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=871325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=875798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876699"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cloop-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-eppic-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-gcore-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:crash-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hdjmod-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ipset-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-xen-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libipset3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-controller-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-pki");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-switch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-switch-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-openvswitch-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-x11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-qt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-websrv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-xend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-xend-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xtables-addons-kmp-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"cloop-2.639-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debuginfo-2.639-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debugsource-2.639-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-debuginfo-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-debuginfo-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-debuginfo-2.639_k3.11.10_11-11.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debuginfo-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debugsource-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-devel-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-debuginfo-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-debuginfo-7.0.2-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-debuginfo-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-debuginfo-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-debuginfo-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-debuginfo-7.0.2_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-debugsource-1.28-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.11.10_11-16.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-6.19-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debuginfo-6.19-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debugsource-6.19-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-devel-6.19-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-debuginfo-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-debuginfo-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-debuginfo-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-debuginfo-6.19_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-1.4.20.3-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debuginfo-1.4.20.3-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debugsource-1.4.20.3-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-debuginfo-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-debuginfo-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-debuginfo-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-debuginfo-1.4.20.3_k3.11.10_11-13.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-vanilla-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-syms-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-6.19-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-debuginfo-6.19-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-1.58-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debuginfo-1.58-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debugsource-1.58-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-1.58_k3.11.10_11-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-debuginfo-1.58_k3.11.10_11-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-1.58_k3.11.10_11-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-debuginfo-1.58_k3.11.10_11-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-1.58_k3.11.10_11-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-debuginfo-1.58_k3.11.10_11-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-debuginfo-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debuginfo-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debugsource-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-debuginfo-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-debuginfo-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-debuginfo-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-debuginfo-1.11.0_k3.11.10_11-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-pki-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-debuginfo-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-test-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-0.44-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debuginfo-0.44-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debugsource-0.44-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-0.44_k3.11.10_11-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.11.10_11-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-0.44_k3.11.10_11-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.11.10_11-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-0.44_k3.11.10_11-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.11.10_11-258.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-test-1.11.0-0.25.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-debuginfo-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debuginfo-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debugsource-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-devel-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-debuginfo-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-debuginfo-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-debuginfo-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.2.18_k3.11.10_11-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-debuginfo-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-debuginfo-4.2.18-2.12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-debugsource-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-devel-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-4.3.2_01_k3.11.10_11-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-debuginfo-4.3.2_01_k3.11.10_11-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-4.3.2_01_k3.11.10_11-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-debuginfo-4.3.2_01_k3.11.10_11-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-4.3.2_01_k3.11.10_11-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-debuginfo-4.3.2_01_k3.11.10_11-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-debuginfo-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-debuginfo-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-2.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debuginfo-2.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debugsource-2.3-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-debuginfo-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-debuginfo-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-debuginfo-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-debuginfo-2.3_k3.11.10_11-2.7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.11.10-11.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-doc-html-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-32bit-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-4.3.2_01-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-debuginfo-4.3.2_01-15.1") ) flag++;

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
