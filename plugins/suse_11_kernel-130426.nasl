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
  script_id(66344);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_cve_id("CVE-2012-2137", "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0311", "CVE-2013-0349", "CVE-2013-0913", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1772", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1848", "CVE-2013-1860", "CVE-2013-2634", "CVE-2013-2635");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 7667 / 7669 / 7675)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel has been updated to 3.0.74 fix
various security issues and bugs :

This update brings some features :

  - Updated HD-audio drivers for Nvidia/AMD HDMI and Haswell
    audio (FATE#314311 FATE#313695)

  - Lustre enablement patches were added (FATE#314679).

  - SGI UV (Ultraviolet) platform support. (FATE#306952)
    Security issues fixed in this update :

  - The hidp_setup_hid function in net/bluetooth/hidp/core.c
    in the Linux kernel did not properly copy a certain name
    field, which allowed local users to obtain sensitive
    information from kernel memory by setting a long name
    and making an HIDPCONNADD ioctl call. (CVE-2013-0349)

  - Buffer overflow in virt/kvm/irq_comm.c in the KVM
    subsystem in the Linux kernel allowed local users to
    cause a denial of service (crash) and to possibly
    execute arbitrary code via vectors related to Message
    Signaled Interrupts (MSI), irq routing entries, and an
    incorrect check by the setup_routing_entry function
    before invoking the kvm_set_irq function.
    (CVE-2012-2137)

  - The isofs_export_encode_fh function in fs/isofs/export.c
    in the Linux kernel did not initialize a certain
    structure member, which allowed local users to obtain
    sensitive information from kernel heap memory via a
    crafted application. (CVE-2012-6549)

  - The udf_encode_fh function in fs/udf/namei.c in the
    Linux kernel did not initialize a certain structure
    member, which allowed local users to obtain sensitive
    information from kernel heap memory via a crafted
    application. (CVE-2012-6548)

  - Timing side channel on attacks were possible on
    /dev/ptmx that could allow local attackers to predict
    keypresses like e.g. passwords. This has been fixed by
    not updating accessed/modified time on the pty devices.
    Note that this might break pty idle detection, so it
    might get reverted again. (CVE-2013-0160)

  - The Xen netback functionality in the Linux kernel
    allowed guest OS users to cause a denial of service
    (loop) by triggering ring pointer corruption.
    (CVE-2013-0216)

  - The pciback_enable_msi function in the PCI backend
    driver (drivers/xen/pciback/conf_space_capability_msi.c)
    in Xen for the Linux allowed guest OS users with PCI
    device access to cause a denial of service via a large
    number of kernel log messages. (CVE-2013-0231)

  - The translate_desc function in drivers/vhost/vhost.c in
    the Linux kernel did not properly handle cross-region
    descriptors, which allowed guest OS users to obtain host
    OS privileges by leveraging KVM guest OS privileges.
    (CVE-2013-0311)

  - Integer overflow in
    drivers/gpu/drm/i915/i915_gem_execbuffer.c in the i915
    driver in the Direct Rendering Manager (DRM) subsystem
    in the Linux kernel allowed local users to cause a
    denial of service (heap-based buffer overflow) or
    possibly have unspecified other impact via a crafted
    application that triggers many relocation copies, and
    potentially leads to a race condition. (CVE-2013-0913)

  - The flush_signal_handlers function in kernel/signal.c in
    the Linux kernel preserved the value of the sa_restorer
    field across an exec operation, which makes it easier
    for local users to bypass the ASLR protection mechanism
    via a crafted application containing a sigaction system
    call. (CVE-2013-0914)

  - Use-after-free vulnerability in the shmem_remount_fs
    function in mm/shmem.c in the Linux kernel allowed local
    users to gain privileges or to cause a denial of service
    (system crash) by remounting a tmpfs filesystem without
    specifying a required mpol (aka mempolicy) mount option.
    (CVE-2013-1767)

  - The log_prefix function in kernel/printk.c in the Linux
    kernel 3.x did not properly remove a prefix string from
    a syslog header, which allowed local users to cause a
    denial of service (buffer overflow and system crash) by
    leveraging /dev/kmsg write access and triggering a
    call_console_drivers function call. (CVE-2013-1772)

  - The chase_port function in drivers/usb/serial/io_ti.c in
    the Linux kernel allowed local users to cause a denial
    of service (NULL pointer dereference and system crash)
    via an attempted /dev/ttyUSB read or write operation on
    a disconnected Edgeport USB serial converter.
    (CVE-2013-1774)

  - Race condition in the install_user_keyrings function in
    security/keys/process_keys.c in the Linux kernel allowed
    local users to cause a denial of service (NULL pointer
    dereference and system crash) via crafted keyctl system
    calls that trigger keyring operations in simultaneous
    threads. (CVE-2013-1792)

  - The kvm_set_msr_common function in arch/x86/kvm/x86.c in
    the Linux kernel did not ensure a required time_page
    alignment during an MSR_KVM_SYSTEM_TIME operation, which
    allowed guest OS users to cause a denial of service
    (buffer overflow and host OS memory corruption) or
    possibly have unspecified other impact via a crafted
    application. (CVE-2013-1796)

  - Use-after-free vulnerability in arch/x86/kvm/x86.c in
    the Linux kernel allowed guest OS users to cause a
    denial of service (host OS memory corruption) or
    possibly have unspecified other impact via a crafted
    application that triggers use of a guest physical
    address (GPA) in (1) movable or (2) removable memory
    during an MSR_KVM_SYSTEM_TIME kvm_set_msr_common
    operation. (CVE-2013-1797)

  - The ioapic_read_indirect function in virt/kvm/ioapic.c
    in the Linux kernel did not properly handle a certain
    combination of invalid IOAPIC_REG_SELECT and
    IOAPIC_REG_WINDOW operations, which allows guest OS
    users to obtain sensitive information from host OS
    memory or cause a denial of service (host OS OOPS) via a
    crafted application. (CVE-2013-1798)

  - fs/ext3/super.c in the Linux kernel used incorrect
    arguments to functions in certain circumstances related
    to printk input, which allowed local users to conduct
    format-string attacks and possibly gain privileges via a
    crafted application. (CVE-2013-1848)

  - Heap-based buffer overflow in the wdm_in_callback
    function in drivers/usb/class/cdc-wdm.c in the Linux
    kernel allowed physically proximate attackers to cause a
    denial of service (system crash) or to possibly execute
    arbitrary code via a crafted cdc-wdm USB device.
    (CVE-2013-1860)

  - net/dcb/dcbnl.c in the Linux kernel did not initialize
    certain structures, which allowed local users to obtain
    sensitive information from kernel stack memory via a
    crafted application. (CVE-2013-2634)

  - The rtnl_fill_ifinfo function in net/core/rtnetlink.c in
    the Linux kernel did not initialize a certain structure
    member, which allowed local users to obtain sensitive
    information from kernel stack memory via a crafted
    application. (CVE-2013-2635)

  - The msr_open function in arch/x86/kernel/msr.c in the
    Linux kernel allowed local users to bypass intended
    capability restrictions by executing a crafted
    application as root, as demonstrated by msr32.c.
    (CVE-2013-0268)

Bugs fixed in this update :

BTRFS :

  - btrfs: do not try to notify udev about missing devices.

  - btrfs: add cancellation points to defrag.

  - btrfs: define BTRFS_MAGIC as a u64 value.

  - btrfs: make sure NODATACOW also gets NODATASUM set.

  - btrfs: enforce min_bytes parameter during extent
    allocation.

  - btrfs: build up error handling for merge_reloc_roots.

  - btrfs: free all recorded tree blocks on error .

  - btrfs: do not BUG_ON in prepare_to_reloc .

  - btrfs: do not BUG_ON on aborted situation .

  - btrfs: handle a bogus chunk tree nicely .

  - btrfs: do not drop path when printing out tree errors in
    scrub .

  - btrfs: make subvol creation/deletion killable in the
    early stages.

  - btrfs: abort unlink trans in missed error case.

  - btrfs: fix reada debug code compilation.

  - btrfs: return error when we specify wrong start to
    defrag.

  - btrfs: do not force pages under writeback to finish when
    aborting. USB :

  - USB: move usb_translate_errors to 1/usb. (bnc#806908)

  - USB: add EOPNOTSUPP to usb_translate_errors.
    (bnc#806908)

  - USB: cdc-wdm: sanitize error returns. (bnc#806908)

  - USB: cdc-wdm: cleanup error codes. (bnc#806908)

  - USB: cdc-wdm: add helper to preserve kABI. (bnc#806908)

  - USB: Do not use EHCI port sempahore for USB 3.0 hubs.
    (bnc#807560)

  - USB: Prepare for refactoring by adding extra udev
    checks. (bnc#807560)

  - USB: Rip out recursive call on warm port reset.
    (bnc#807560)

  - USB: Fix connected device switch to Inactive state.
    (bnc#807560)

  - USB: modify hub to detect unplugs in all states.
    (bnc#807560)

  - USB: io_ti: Fix NULL dereference in chase_port().
    (bnc#806976, CVE-2013-1774)

  - USB: cdc-wdm: fix buffer overflow. (bnc#806431)

  - USB: cdc-wdm: cannot use dev_printk when device is gone.
    (bnc#806469)

  - USB: cdc-wdm: fix memory leak. (bnc#806466)

  - elousb: really long delays for broken devices.
    (bnc#795269)

  - xhci: Fix conditional check in bandwidth calculation.
    (bnc#795961)

  - xHCI: Fix TD Size calculation on 1.0 hosts. (bnc#795957)

  - xhci: avoid dead ports, add roothub port polling.
    (bnc#799197)

  - USB: Handle warm reset failure on empty port.
    (bnc#799926)

  - USB: Ignore port state until reset completes.
    (bnc#799926)

  - Allow USB 3.0 ports to be disabled. (bnc#799926)

  - USB: Ignore xHCI Reset Device status. (bnc#799926)

  - USB: Handle auto-transition from hot to warm reset
    (bnc#799926). S/390 :

  - ipl: Implement diag308 loop for zfcpdump (bnc#801720,
    LTC#88197).

  - zcore: Add hsa file (bnc#801720, LTC#88198).

  - kernel: support physical memory > 4TB (bnc#801720,
    LTC#88787).

  - mm: Fix crst upgrade of mmap with MAP_FIXED (bnc#801720,
    LTC#88797).

  - Update patches.suse/zcrypt-feed-hwrandom (bnc#806825).
    Allow zcrypt module unload even when the thread is
    blocked writing to a full random pool.

  - dca: check against empty dca_domains list before
    unregister provider fix.

  - s390/kvm: Fix store status for ACRS/FPRS fix.

  - series.conf: disabled
    patches.arch/s390-64-03-kernel-inc-phys-mem.patch due to
    excessive kabi break. (bnc#801720)

ALSA :

  -
    patches.drivers/alsa-sp3-pre-695-Yet-another-fix-for-bro
    ken-HSW-HDMI-pin: Refresh. Fix the invalid PCI SSID
    check. (bnc#806404)

  - ALSA: hda - Support mute LED on HP AiO buttons.
    (bnc#808991)

  - ALSA: hda: Allow multple SPDIF controls per codec.
    (bnc#780977)

  - ALSA: hda: Virtualize SPDIF out controls. (bnc#780977)

  - ALSA: hda: Separate generic and non-generic
    implementations.

  - ALSA: hda: hdmi_eld_update_pcm_info: update a stream in
    place.

  - ALSA: hda: HDMI: Support codecs with fewer cvts than
    pins.

  - ALSA: hda - Add snd_hda_get_conn_list() helper function.

  - ALSA: hda - Add snd_hda_override_conn_list() helper
    function.

  - ALSA: hda - Increase the max number of coverters/pins in
    patch_hdmi.c. (bnc#780977)

  - ALSA: hda - Check non-snoop in a single place.
    (bnc#801713)

  - ALSA: HDA: Use LPIB Position fix for Intel SCH Poulsbo.
    (bnc#801713)

  - ALSA: hda_intel: Add Oaktrail identifiers. (bnc#801713)

  - ALSA: HDA: Use LPIB position fix for Oaktrail.
    (bnc#801713)

  - ALSA: hda - add id for Atom Cedar Trail HDMI codec.
    (bnc#801713)

  - ALSA: hda - Fix detection of Creative SoundCore3D
    controllers. (bnc#762424)

  - ALSA: hda - add power states information in proc.
    (bnc#801713)

  - ALSA: hda - Show D3cold state in proc files.
    (bnc#801713)

  - ALSA: hda - check supported power states. (bnc#801713)

  - ALSA: hda - reduce msleep time if EPSS power states
    supported. (bnc#801713)

  - ALSA: hda - check proper return value. (bnc#801713)

  - ALSA: hda - power setting error check. (bnc#801713)

  - ALSA: hda - Add DeviceID for Haswell HDA. (bnc#801713)

  - ALSA: hda - add Haswell HDMI codec id. (bnc#801713)

  - ALSA: hda - Fix driver type of Haswell controller to
    AZX_DRIVER_SCH.

  - ALSA: hda - Add new GPU codec ID to snd-hda.
    (bnc#780977)

  - ALSA: HDMI - Fix channel_allocation array wrong order.
    (bnc#801713)

  - ALSA: hda - Avoid BDL position workaround when
    no_period_wakeup is set. (bnc#801713)

  - ALSA: hda - Allow to pass position_fix=0 explicitly.
    (bnc#801713)

  - ALSA: hda - Add another pci id for Haswell board.

  - ALSA: hda - force use of SSYNC bits. (bnc#801713)

  - ALSA: hda - use LPIB for delay estimation. (bnc#801713)

  - ALSA: hda - add PCI identifier for Intel 5 Series/3400.
    (bnc#801713)

  - ALSA: hda - Add workaround for conflicting IEC958
    controls (FATE#314311).

  - ALSA: hda - Stop LPIB delay counting on broken hardware
    (FATE#313695).

  - ALSA: hda - Always turn on pins for HDMI/DP
    (FATE#313695).

  - ALSA: hda - bug fix for invalid connection list of
    Haswell HDMI codec pins (FATE#313695).

  - ALSA - HDA: New PCI ID for Haswell ULT. (bnc#801713)

  - ALSA: hda - Release assigned pin/cvt at error path of
    hdmi_pcm_open(). (bnc#801713)

  - ALSA: hda - Support rereading widgets under the function
    group. (bnc#801713)

  - ALSA: hda - Add fixup for Haswell to enable all pin and
    convertor widgets. (bnc#801713)

  - ALSA: hda - Yet another fix for broken HSW HDMI pin
    connections. (bnc#801713)

  - patches.kabi/alsa-spdif-update-kabi-fixes: Fix kABI
    breakage due to HD-audio HDMI updates. (bnc#780977)

  - ALSA: hda - Fix non-snoop page handling. (bnc#800701)

  - ALSA: hda - Apply mic-mute LED fixup for new HP laptops.
    (bnc#796418)

  -
    patches.drivers/alsa-sp3-pre-695-Yet-another-fix-for-bro
    ken-HSW-HDMI-pin: Refresh. Fix a superfluous incremental
    leading to the double array size. (bnc#808966)

XEN :

  - pciback: notify hypervisor about devices intended to be
    assigned to guests.

  - patches.xen/xen-clockevents: Update. (bnc#803712)

  - patches.xen/xen-ipi-per-cpu-irq: Update. (bnc#803712)

  - patches.xen/xen3-patch-2.6.19: Update. (bnc#809166)

  - Update Xen patches to 3.0.68.

  - Update Xen patches to 3.0.63.

  - netback: fix netbk_count_requests().

  - x86/mm: Check if PUD is large when validating a
    kerneladdress (bnc#794805). OTHER :

  - Revert dmi_scan: fix missing check for _DMI_ signature
    in smbios_present().

  - Revert drivers/firmware/dmi_scan.c: fetch dmi version
    from SMBIOS if it exists.

  - Revert drivers/firmware/dmi_scan.c: check dmi version
    when get system uuid.

  - sysfs: Revert sysfs: fix race between readdir and lseek.
    (bnc#816443)

  - 8021q: Revert 8021q: fix a potential use-after-free.

  - /dev/urandom returning EOF: trim down revert to not
    change kabi. . (bnc#789359)

  - tun: reserves space for network in skb. (bnc#803394)

  - Fixed /dev/urandom returning EOF. (bnc#789359)

  - mm: Make snapshotting pages for stable writes a per-bio
    operation

  - fs: Only enable stable page writes when necessary.
    (bnc#807517)

  -
    patches.drivers/ixgbe-Address-fact-that-RSC-was-not-sett
    ing-GSO-size.patch: Fix. (bnc#802712)

  - Fix build error without CONFIG_BOOTSPLASH

  - Fix bootsplash breakage due to 3.0.67 stable fix.
    (bnc#813963)

  - drivers/base/memory.c: fix memory_dev_init() long delay.
    (bnc#804609)

  - mtd: drop physmap_configure. (bnc#809375)

  - Bluetooth: btusb: hide more usb_submit_urb errors.
    (bnc#812281)

  - o2dlm: fix NULL pointer dereference in
    o2dlm_blocking_ast_wrapper. (bnc#806492)

  - qeth: fix qeth_wait_for_threads() deadlock for OSN
    devices (bnc#812315, LTC#90910).

  - Fix NULL pointer dereference in
    o2dlm_blocking_ast_wrapper. (bnc#806492)

  - mm: fix ALLOC_WMARK_MASK check. (bnc#808166)

  - pciehp: Fix dmi match table definition and missing space
    in printk. (bnc#796412)

  - fnic: Fix SGEs limit. (bnc#807431)

  - pciehp: Ignore missing surprise bit on some hosts.
    (bnc#796412)

  - ipv6: Queue fragments per interface for
    multicast/link-local addresses. (bnc#804220)

  - netfilter: send ICMPv6 message on fragment reassembly
    timeout. (bnc#773577)

  - netfilter: fix sending ICMPv6 on netfilter reassembly
    timeout. (bnc#773577)

  - jbd: clear revoked flag on buffers before a new
    transaction started. (bnc#806395)

  - xfrm6: count extension headers into payload length.
    (bnc#794513)

  - mm: page_alloc: Avoid marking zones full prematurely
    after zone_reclaim() (Evict inactive pages when
    zone_reclaim is enabled (bnc#808166)).

  - st: Take additional queue ref in st_probe. (bnc#801038,
    bnc#788826)

  - drivers: xhci: fix incorrect bit test. (bnc#714604)

  - xfrm: remove unused xfrm4_policy_fini(). (bnc#801717)

  - xfrm: make gc_thresh configurable in all namespaces.
    (bnc#801717)

  - kabi: use net_generic to avoid changes in struct net.
    (bnc#801717)

  - xfs: Fix WARN_ON(delalloc) in xfs_vm_releasepage().
    (bnc#806631)

  -
    patches.drivers/alsa-sp2-hda-033-Support-mute-LED-on-HP-
    AiO-buttons: Refresh tags.

  - block: use i_size_write() in bd_set_size(). (bnc#809748)

  - loopdev: fix a deadlock. (bnc#809748)

  - patches.suse/supported-flag: fix mis-reported supported
    status. (bnc#809493)

  - patches.suse/supported-flag-enterprise: Refresh.

  - KVM: Convert MSR_KVM_SYSTEM_TIME to use
    gfn_to_hva_cache_init. (bnc#806980 / CVE-2013-1797)

  - KVM: Fix bounds checking in ioapic indirect register
    read. (bnc#806980 / CVE-2013-1798)

  - KVM: Fix for buffer overflow in handling of
    MSR_KVM_SYSTEM_TIME. (bnc#806980 / CVE-2013-1796)

  - KVM: introduce kvm_read_guest_cached. (bnc#806980)

  - x86/numa: Add constraints check for nid parameters (Cope
    with negative SRAT distances (bnc#807853)).

  - drm/i915: Periodically sanity check power management.
    (bnc#808307)

  - drm/i915: bounds check execbuffer relocation count.
    (bnc#808829,CVE-2013-0913)

  - ext3: Fix format string issues. (bnc#809155,
    CVE-2013-1848)

  - x86-64: Fix memset() to support sizes of 4Gb and above
    (Properly initialise memmap on large machines
    (bnc#802353)).

  - bdi: allow block devices to say that they require stable
    page writes

  - mm: only enforce stable page writes if the backing
    device requires it

  - block: optionally snapshot page contents to provide
    stable pages during write

  - 9pfs: fix filesystem to wait for stable page writeback

  - ocfs2: wait for page writeback to provide stable pages

  - ubifs: wait for page writeback to provide stable pages

  - Only enable stable page writes when required by
    underlying BDI. (bnc#807517)

  - KVM: emulator: drop RPL check from linearize() function.
    (bnc#754583)

  - mlx4: Correct calls to to_ib_ah_attr(). (bnc#806847)

  - DRM/i915: On G45 enable cursor plane briefly after
    enabling the display plane (bnc#753371) [backported from
    drm-intel-fixes].

  - cxgb4i: Remove the scsi host device when removing
    device. (bnc#722398)

  - xprtrdma: The transport should not bug-check when a dup
    reply is received. (bnc#763494)

  - tmpfs: fix use-after-free of mempolicy object.
    (bnc#806138, CVE-2013-1767)

  - lpfc: Check fc_block_scsi_eh return value correctly for
    lpfc_abort_handler. (bnc#803674)

  - md: fix bug in handling of new_data_offset. (bnc#805823)

  - md: Avoid OOPS when reshaping raid1 to raid0 (Useful
    OOPS fix).

  - md: fix two bugs when attempting to resize RAID0 array
    (Useful BUG() fix).

  - md: raid0: fix error return from create_stripe_zones
    (useful bug fix).

  - ext4: add missing kfree() on error return path in
    add_new_gdb().

  - ext4: Free resources in some error path in
    ext4_fill_super.

  - intel_idle: support Haswell (fate#313720).

  - hp_accel: Add a new PnP ID HPQ6007 for new HP laptops.
    (bnc#802445)

  - nfs: Ensure NFS does not block on dead server during
    unmount. (bnc#794529)

  - block: disable discard request merge temporarily.
    (bnc#803067)

  - mm: mmu_notifier: have mmu_notifiers use a global SRCU
    so they may safely schedule

  - mm: mmu_notifier: make the mmu_notifier srcu static

  - mmu_notifier_unregister NULL pointer deref and multiple
    ->release() callouts

  - Have mmu_notifiers use SRCU so they may safely schedule
    kabi compatability

  -
    patches.fixes/Have-mmu_notifiers-use-SRCU-so-they-may-sa
    fely-schedule.patch :

  -
    patches.fixes/Have-mmu_notifiers-use-SRCU-so-they-may-sa
    fely-schedule-build-fix.patch: Delete, replace with
    upstream equivalent and add KABI workaround (bnc#578046,
    bnc#786814, FATE#306952).

  - ipv6: Do not send packet to big messages to self.
    (bnc#786150)

  - hpwdt: Unregister NMI events on exit. (bnc#777746)

  - x86/mm: Check if PUD is large when validating a kernel
    address. (bnc#794805)

  - ata: Fix DVD not dectected at some Haswell platforms.
    (bnc#792674)

  - Avoid softlockups in printk. (bnc#744692, bnc#789311)

  - Do not pack credentials for dying processes.
    (bnc#779577, bnc#803056)

  - xfs: punch new delalloc blocks out of failed writes
    inside EOF. (bnc#761849)

  - xfs: xfs_sync_data is redundant. (bnc#761849)

  - Add GPIO support for Intel Centerton SOC. (bnc#792793)

  - Add Multifunction Device support for Intel Centerton
    SOC. (bnc#792793)

  - Add Intel Legacy Block support for Intel Centerton SOC.
    (bnc#792793)

  - mm: net: Allow some !SOCK_MEMALLOC traffic through even
    if skb_pfmemalloc (Allow GPFS network traffic despite
    PF_MEMALLOC misuse (bnc#786900)).

  - kernel/resource.c: fix stack overflow in
    __reserve_region_with_split(). (bnc#801782)

  - Lustre enablement patches

  - block: add dev_check_rdonly and friends for Lustre
    testing (FATE#314679).

  - dcache: Add DCACHE_LUSTRE_INVALID flag for Lustre to
    handle its own invalidation (FATE#314679).

  - lsm: export security_inode_unlink (FATE#315679).

  - lustre: Add lustre kernel version (FATE#314679).

  - st: fix memory leak with >1MB tape I/O. (bnc#798921)

  - cifs: lower default wsize when 1 extensions are not
    used. (bnc#799578)

  - ata_generic: Skip is_intel_ider() check when
    ata_generic=1 is set. (bnc#777616)

  - quota: autoload the quota_v2 module for QFMT_VFS_V1
    quota format. (bnc#802153)

  - xen: properly bound buffer access when parsing
    cpu/availability.

  - netback: shutdown the ring if it contains garbage
    (CVE-2013-0216 XSA-39 bnc#800280).

  - netback: correct netbk_tx_err() to handle wrap around
    (CVE-2013-0216 XSA-39 bnc#800280).

  - pciback: rate limit error message from
    pciback_enable_msi() (CVE-2013-0231 XSA-43 bnc#801178).

  - scsiback/usbback: move cond_resched() invocations to
    proper place.

  - drm/i915: Implement workaround for broken CS tlb on
    i830/845. (bnc#758040)

  - drivers: scsi: storvsc: Initialize the sglist.

  - e1000e: 82571 Fix Tx Data Corruption during Tx hang
    recovery. (bnc#790867)

  - KVM: Fix buffer overflow in kvm_set_irq(). (bnc#767612 /
    CVE-2012-2137)

  - mm: compaction: Abort async compaction if locks are
    contended or taking too long.

  - mm: compaction: abort compaction loop if lock is
    contended or run too long.

  - mm: compaction: acquire the zone->lock as late as
    possible.

  - mm: compaction: acquire the zone->lru_lock as late as
    possible.

  - mm: compaction: move fatal signal check out of
    compact_checklock_irqsave. Reduce LRU and zone lock
    contention when compacting memory for THP. (bnc#796823)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578046"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=651219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=722398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=730117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=736149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776787"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780977"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786814"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=786900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=787821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=788826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=790867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=792793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=793671"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=794805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=795269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=795928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=795957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=795961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=799926"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801720"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=802712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=804656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806138"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807431"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808307"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809493"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=810473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812315"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813963"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2137.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-6549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0268.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0311.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0349.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0914.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1792.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1796.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1798.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1860.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2634.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2635.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 7667 / 7669 / 7675 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/08");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.4_02_3.0.74_0.6.6-0.5.22")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.4_02_3.0.74_0.6.6-0.5.22")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.74-0.6.6.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-default-4.1.4_02_3.0.74_0.6.6-0.5.22")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"xen-kmp-trace-4.1.4_02_3.0.74_0.6.6-0.5.22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
