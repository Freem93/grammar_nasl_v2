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
  script_id(80250);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/26 14:03:25 $");

  script_cve_id("CVE-2012-4398", "CVE-2013-2889", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-7263", "CVE-2014-3181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-4508", "CVE-2014-4608", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-8133", "CVE-2014-8709", "CVE-2014-8884", "CVE-2014-9090", "CVE-2014-9322");

  script_name(english:"SuSE 11.3 Security Update : Linux kernel (SAT Patch Number 10103)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to
fix various bugs and security issues.

The following security bugs have been fixed :

  - The __request_module function in kernel/kmod.c in the
    Linux kernel before 3.4 did not set a certain killable
    attribute, which allowed local users to cause a denial
    of service (memory consumption) via a crafted
    application. (bnc#779488). (CVE-2012-4398)

  - drivers/hid/hid-zpff.c in the Human Interface Device
    (HID) subsystem in the Linux kernel through 3.11, when
    CONFIG_HID_ZEROPLUS is enabled, allowed physically
    proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted device.
    (bnc#835839). (CVE-2013-2889)

  - The Human Interface Device (HID) subsystem in the Linux
    kernel through 3.11, when CONFIG_LOGITECH_FF,
    CONFIG_LOGIG940_FF, or CONFIG_LOGIWHEELS_FF is enabled,
    allowed physically proximate attackers to cause a denial
    of service (heap-based out-of-bounds write) via a
    crafted device, related to (1) drivers/hid/hid-lgff.c,
    (2) drivers/hid/hid-lg3ff.c, and (3)
    drivers/hid/hid-lg4ff.c. (bnc#835839). (CVE-2013-2893)

  - Multiple array index errors in
    drivers/hid/hid-multitouch.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through 3.11,
    when CONFIG_HID_MULTITOUCH is enabled, allowed
    physically proximate attackers to cause a denial of
    service (heap memory corruption, or NULL pointer
    dereference and OOPS) via a crafted device.
    (bnc#835839). (CVE-2013-2897)

  - drivers/hid/hid-picolcd_core.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through 3.11,
    when CONFIG_HID_PICOLCD is enabled, allowed physically
    proximate attackers to cause a denial of service (NULL
    pointer dereference and OOPS) via a crafted device.
    (bnc#835839). (CVE-2013-2899)

  - The Linux kernel before 3.12.4 updates certain length
    values before ensuring that associated data structures
    have been initialized, which allowed local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call, related to net/ipv4/ping.c, net/ipv4/raw.c,
    net/ipv4/udp.c, net/ipv6/raw.c, and net/ipv6/udp.c.
    (bnc#853040, bnc#857643). (CVE-2013-7263)

  - Multiple stack-based buffer overflows in the
    magicmouse_raw_event function in
    drivers/hid/hid-magicmouse.c in the Magic Mouse HID
    driver in the Linux kernel through 3.16.3 allowed
    physically proximate attackers to cause a denial of
    service (system crash) or possibly execute arbitrary
    code via a crafted device that provides a large amount
    of (1) EHCI or (2) XHCI data associated with an event.
    (bnc#896382). (CVE-2014-3181)

  - The report_fixup functions in the HID subsystem in the
    Linux kernel before 3.16.2 allowed physically proximate
    attackers to cause a denial of service (out-of-bounds
    write) via a crafted device that provides a small report
    descriptor, related to (1) drivers/hid/hid-cherry.c, (2)
    drivers/hid/hid-kye.c, (3) drivers/hid/hid-lg.c, (4)
    drivers/hid/hid-monterey.c, (5)
    drivers/hid/hid-petalynx.c, and (6)
    drivers/hid/hid-sunplus.c. (bnc#896390). (CVE-2014-3184)

  - Multiple buffer overflows in the
    command_port_read_callback function in
    drivers/usb/serial/whiteheat.c in the Whiteheat USB
    Serial Driver in the Linux kernel before 3.16.2 allowed
    physically proximate attackers to execute arbitrary code
    or cause a denial of service (memory corruption and
    system crash) via a crafted device that provides a large
    amount of (1) EHCI or (2) XHCI data associated with a
    bulk response. (bnc#896391). (CVE-2014-3185)

  - Buffer overflow in the picolcd_raw_event function in
    devices/hid/hid-picolcd_core.c in the PicoLCD HID device
    driver in the Linux kernel through 3.16.3, as used in
    Android on Nexus 7 devices, allowed physically proximate
    attackers to cause a denial of service (system crash) or
    possibly execute arbitrary code via a crafted device
    that sends a large report. (bnc#896392). (CVE-2014-3186)

  - The kvm_iommu_map_pages function in virt/kvm/iommu.c in
    the Linux kernel through 3.16.1 miscalculated the number
    of pages during the handling of a mapping failure, which
    allowed guest OS users to (1) cause a denial of service
    (host OS memory corruption) or possibly have unspecified
    other impact by triggering a large gfn value or (2)
    cause a denial of service (host OS memory consumption)
    by triggering a small gfn value that leads to
    permanently pinned pages. (bnc#892782). (CVE-2014-3601)

  - The WRMSR processing functionality in the KVM subsystem
    in the Linux kernel through 3.17.2 did not properly
    handle the writing of a non-canonical address to a
    model-specific register, which allowed guest OS users to
    cause a denial of service (host OS crash) by leveraging
    guest OS privileges, related to the wrmsr_interception
    function in arch/x86/kvm/svm.c and the handle_wrmsr
    function in arch/x86/kvm/vmx.c. (bnc#899192).
    (CVE-2014-3610)

  - arch/x86/kvm/vmx.c in the KVM subsystem in the Linux
    kernel through 3.17.2 did not have an exit handler for
    the INVVPID instruction, which allowed guest OS users to
    cause a denial of service (guest OS crash) via a crafted
    application. (bnc#899192). (CVE-2014-3646)

  - arch/x86/kvm/emulate.c in the KVM subsystem in the Linux
    kernel through 3.17.2 did not properly perform RIP
    changes, which allowed guest OS users to cause a denial
    of service (guest OS crash) via a crafted application.
    (bnc#899192). (CVE-2014-3647)

  - The SCTP implementation in the Linux kernel through
    3.17.2 allowed remote attackers to cause a denial of
    service (system crash) via a malformed ASCONF chunk,
    related to net/sctp/sm_make_chunk.c and
    net/sctp/sm_statefuns.c. (bnc#902346, bnc#902349).
    (CVE-2014-3673)

  - arch/x86/kernel/entry_32.S in the Linux kernel through
    3.15.1 on 32-bit x86 platforms, when syscall auditing is
    enabled and the sep CPU feature flag is set, allowed
    local users to cause a denial of service (OOPS and
    system crash) via an invalid syscall number, as
    demonstrated by number 1000. (bnc#883724).
    (CVE-2014-4508)

  - * DISPUTED * Multiple integer overflows in the
    lzo1x_decompress_safe function in
    lib/lzo/lzo1x_decompress_safe.c in the LZO decompressor
    in the Linux kernel before 3.15.2 allowed
    context-dependent attackers to cause a denial of service
    (memory corruption) via a crafted Literal Run. NOTE: the
    author of the LZO algorithms says: The Linux kernel is
    not affected; media hype. (bnc#883948). (CVE-2014-4608)

  - kernel/trace/trace_syscalls.c in the Linux kernel
    through 3.17.2 did not properly handle private syscall
    numbers during use of the ftrace subsystem, which
    allowed local users to gain privileges or cause a denial
    of service (invalid pointer dereference) via a crafted
    application. (bnc#904013). (CVE-2014-7826)

  - An SCTP server doing ASCONF would panic on malformed
    INIT ping-of-death. (bnc#905100). (CVE-2014-7841)

  - The ieee80211_fragment function in net/mac80211/tx.c in
    the Linux kernel before 3.13.5 did not properly maintain
    a certain tail pointer, which allowed remote attackers
    to obtain sensitive cleartext information by reading
    packets. (bnc#904700). (CVE-2014-8709)

  - A local user with write access could have used this flaw
    to crash the kernel or elevate privileges (bnc#905522).
    The following non-security bugs have been fixed:.
    (CVE-2014-8884)

  - Build the KOTD against the SP3 Update project

  - HID: fix kabi breakage.

  - NFS: Provide stub nfs_fscache_wait_on_invalidate() for
    when CONFIG_NFS_FSCACHE=n.

  - NFS: fix inverted test for delegation in
    nfs4_reclaim_open_state. (bnc#903331)

  - NFS: remove incorrect Lock reclaim failed! warning.
    (bnc#903331)

  - NFSv4: nfs4_open_done first must check that GETATTR
    decoded a file type. (bnc#899574)

  - PCI: pciehp: Clear Data Link Layer State Changed during
    init. (bnc#898295)

  - PCI: pciehp: Enable link state change notifications.
    (bnc#898295)

  - PCI: pciehp: Handle push button event asynchronously.
    (bnc#898295)

  - PCI: pciehp: Make check_link_active() non-static.
    (bnc#898295)

  - PCI: pciehp: Use link change notifications for hot-plug
    and removal. (bnc#898295)

  - PCI: pciehp: Use per-slot workqueues to avoid deadlock.
    (bnc#898295)

  - PCI: pciehp: Use symbolic constants, not hard-coded
    bitmask. (bnc#898295)

  - PM / hibernate: Iterate over set bits instead of PFNs in
    swsusp_free(). (bnc#860441)

  - be2net: Fix invocation of be_close() after be_clear().
    (bnc#895468)

  - block: Fix bogus partition statistics reports.
    (bnc#885077 / bnc#891211)

  - block: Fix computation of merged request priority.

  - btrfs: Fix wrong device size when we are resizing the
    device.

  - btrfs: Return right extent when fiemap gives unaligned
    offset and len.

  - btrfs: abtract out range locking in clone ioctl().

  - btrfs: always choose work from prio_head first.

  - btrfs: balance delayed inode updates.

  - btrfs: cache extent states in defrag code path.

  - btrfs: check file extent type before anything else.
    (bnc#897694)

  - btrfs: clone, do not create invalid hole extent map.

  - btrfs: correctly determine if blocks are shared in
    btrfs_compare_trees.

  - btrfs: do not bug_on if we try to cow a free space cache
    inode.

  - btrfs: ensure btrfs_prev_leaf does not miss 1 item.

  - btrfs: ensure readers see new data after a clone
    operation.

  - btrfs: fill_holes: Fix slot number passed to
    hole_mergeable() call.

  - btrfs: filter invalid arg for btrfs resize.

  - btrfs: fix EINVAL checks in btrfs_clone.

  - btrfs: fix EIO on reading file after ioctl clone works
    on it.

  - btrfs: fix a crash of clone with inline extents split.

  - btrfs: fix crash of compressed writes. (bnc#898375)

  - btrfs: fix crash when starting transaction.

  - btrfs: fix deadlock with nested trans handles.

  - btrfs: fix hang on error (such as ENOSPC) when writing
    extent pages.

  - btrfs: fix leaf corruption after __btrfs_drop_extents.

  - btrfs: fix race between balance recovery and root
    deletion.

  - btrfs: fix wrong extent mapping for DirectIO.

  - btrfs: handle a missing extent for the first file
    extent.

  - btrfs: limit delalloc pages outside of
    find_delalloc_range. (bnc#898375)

  - btrfs: read lock extent buffer while walking backrefs.

  - btrfs: remove unused wait queue in struct extent_buffer.

  - btrfs: replace EINVAL with ERANGE for resize when
    ULLONG_MAX.

  - btrfs: replace error code from btrfs_drop_extents.

  - btrfs: unlock extent and pages on error in
    cow_file_range.

  - btrfs: unlock inodes in correct order in clone ioctl.

  - btrfs_ioctl_clone: Move clone code into its own
    function.

  - cifs: delay super block destruction until all
    cifsFileInfo objects are gone. (bnc#903653)

  - drm/i915: Flush the PTEs after updating them before
    suspend. (bnc#901638)

  - drm/i915: Undo gtt scratch pte unmapping again.
    (bnc#901638)

  - ext3: return 32/64-bit dir name hash according to usage
    type. (bnc#898554)

  - ext4: return 32/64-bit dir name hash according to usage
    type. (bnc#898554)

  - fix: use after free of xfs workqueues. (bnc#894895)

  - fs: add new FMODE flags: FMODE_32bithash and
    FMODE_64bithash. (bnc#898554)

  - futex: Ensure get_futex_key_refs() always implies a
    barrier (bnc#851603 (futex scalability series)).

  - futex: Fix a race condition between REQUEUE_PI and task
    death (bnc#851603 (futex scalability series)).

  - ipv6: add support of peer address. (bnc#896415)

  - ipv6: fix a refcnt leak with peer addr. (bnc#896415)

  - megaraid_sas: Disable fastpath writes for non-RAID0.
    (bnc#897502)

  - mm: change __remove_pages() to call
    release_mem_region_adjustable(). (bnc#891790)

  - netxen: Fix link event handling. (bnc#873228)

  - netxen: fix link notification order. (bnc#873228)

  - nfsd: rename int access to int may_flags in nfsd_open().
    (bnc#898554)

  - nfsd: vfs_llseek() with 32 or 64 bit offsets (hashes).
    (bnc#898554)

  - ocfs2: fix NULL pointer dereference in
    ocfs2_duplicate_clusters_by_page. (bnc#899843)

  - powerpc: Add smp_mb() to arch_spin_is_locked()
    (bsc#893758).

  - powerpc: Add smp_mb()s to arch_spin_unlock_wait()
    (bsc#893758).

  - powerpc: Add support for the optimised lockref
    implementation (bsc#893758).

  - powerpc: Implement arch_spin_is_locked() using
    arch_spin_value_unlocked() (bsc#893758).

  - refresh patches.xen/xen-blkback-multi-page-ring
    (bnc#897708)).

  - remove filesize checks for sync I/O journal commit.
    (bnc#800255)

  - resource: add __adjust_resource() for internal use.
    (bnc#891790)

  - resource: add release_mem_region_adjustable().
    (bnc#891790)

  - revert PM / Hibernate: Iterate over set bits instead of
    PFNs in swsusp_free(). (bnc#860441)

  - rpm/mkspec: Generate specfiles according to Factory
    requirements.

  - rpm/mkspec: Generate a per-architecture per-package
    _constraints file

  - sched: Fix unreleased llc_shared_mask bit during CPU
    hotplug. (bnc#891368)

  - scsi_dh_alua: disable ALUA handling for non-disk
    devices. (bnc#876633)

  - usb: Do not re-read descriptors for wired devices in
    usb_authorize_device(). (bnc#904358)

  - usbback: Do not access request fields in shared ring
    more than once.

  - usbhid: add another mouse that needs QUIRK_ALWAYS_POLL.
    (bnc#888607)

  - vfs,proc: guarantee unique inodes in /proc. (bnc#868049)

  - x86, cpu hotplug: Fix stack frame warning
    incheck_irq_vectors_for_cpu_disable(). (bnc#887418)

  - x86, ioremap: Speed up check for RAM pages (Boot time
    optimisations (bnc#895387)).

  - x86: Add check for number of available vectors before
    CPU down. (bnc#887418)

  - x86: optimize resource lookups for ioremap (Boot time
    optimisations (bnc#895387)).

  - x86: use optimized ioresource lookup in ioremap function
    (Boot time optimisations (bnc#895387)).

  - xfs: Do not free EFIs before the EFDs are committed
    (bsc#755743).

  - xfs: Do not reference the EFI after it is freed
    (bsc#755743).

  - xfs: fix cil push sequence after log recovery
    (bsc#755743).

  - zcrypt: support for extended number of ap domains
    (bnc#894058, LTC#117041).

  - zcrypt: toleration of new crypto adapter hardware
    (bnc#894058, LTC#117041)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=851603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=873228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=876633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=883948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=885077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=888607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891211"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=892782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=893758"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=898295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=898375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=898554"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=899192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=899574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=899843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=901638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=902346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=902349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903331"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=905522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=910251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4398.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2889.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2897.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2899.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3610.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3646.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7826.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8133.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8884.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9322.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10103.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-bigsmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.5_02_3.0.101_0.46-0.7.9")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-trace-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-trace-base-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.46.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.5_02_3.0.101_0.46-0.7.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
