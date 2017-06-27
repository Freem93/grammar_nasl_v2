#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-518.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(90783);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/13 14:37:11 $");

  script_cve_id("CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8709", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-0723", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2384", "CVE-2016-2782", "CVE-2016-3139", "CVE-2016-3156");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-518)");
  script_summary(english:"Check for the openSUSE-2016-518 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.1 kernel was updated to 3.12.57 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2015-8785: The fuse_fill_write_pages function in
    fs/fuse/file.c in the Linux kernel allowed local users
    to cause a denial of service (infinite loop) via a
    writev system call that triggers a zero length for the
    first segment of an iov. (bsc#963765)

  - CVE-2015-8551: The PCI backend driver in Xen, when
    running on an x86 system and using Linux as the driver
    domain, allowed local guest administrators to hit BUG
    conditions and cause a denial of service (NULL pointer
    dereference and host OS crash) by leveraging a system
    with access to a passed-through MSI or MSI-X capable
    physical PCI device and a crafted sequence of
    XEN_PCI_OP_* operations, aka 'Linux pciback missing
    sanity checks (bnc#957990).

  - CVE-2015-8552: The PCI backend driver in Xen, when
    running on an x86 system and using Linux as the driver
    domain, allowed local guest administrators to generate a
    continuous stream of WARN messages and cause a denial of
    service (disk consumption) by leveraging a system with
    access to a passed-through MSI or MSI-X capable physical
    PCI device and XEN_PCI_OP_enable_msi operations, aka
    'Linux pciback missing sanity checks (bnc#957990).

  - CVE-2015-8812: A flaw was found in the CXGB3 kernel
    driver when the network was considered congested. The
    kernel would incorrectly misinterpret the congestion as
    an error condition and incorrectly free/clean up the
    skb. When the device would then send the skb's queued,
    these structures would be referenced and may panic the
    system or allow an attacker to escalate privileges in a
    use-after-free scenario.(bsc#966437).

  - CVE-2015-8816: A malicious USB device could cause kernel
    crashes in the in hub_activate() function (bnc#968010).

  - CVE-2016-0723: Race condition in the tty_ioctl function
    in drivers/tty/tty_io.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory or cause a denial of service (use-after-free and
    system crash) by making a TIOCGETD ioctl call during
    processing of a TIOCSETD ioctl call. (bsc#961500)

  - CVE-2016-2184: A malicious USB device could cause kernel
    crashes in the alsa usb-audio device driver
    (bsc#971125).

  - CVE-2016-2384: A double free on the ALSA umidi object
    was fixed. (bsc#966693).

  - CVE-2016-2782: A malicious USB device could cause kernel
    crashes in the visor device driver (bnc#968670).

  - CVE-2016-3139: A malicious USB device could cause kernel
    crashes in the wacom device driver (bnc#970909).

  - CVE-2016-3156: A quadratic algorithm could lead to long
    kernel ipv4 hangs when removing a device with a large
    number of addresses. (bsc#971360).

The following non-security bugs were fixed :

  - acl: Fix problem with setting ACL on directories
    (bsc#867251).

  - acpi / processor: Introduce apic_id in struct processor
    to save parsed APIC id (bsc#959463).

  - alsa: rawmidi: Make snd_rawmidi_transmit() race-free
    (bsc#968018).

  - alsa: seq: Fix leak of pool buffer at concurrent writes
    (bsc#968018).

  - arm: cubox: Add separate cubox configuration.

  - arm: xen: implement multicall hypercall support.

  - block: xen-blkfront: Fix possible NULL ptr dereference
    (bsc#957986 fate#320625).

  -
    btrfs-8394-qgroup-Account-data-space-in-more-proper-timi
    n.patch: (bsc#963193).

  - btrfs: Add handler for invalidate page (bsc#963193).

  - btrfs: check prepare_uptodate_page() error code earlier
    (bnc#966910).

  - btrfs: delayed_ref: Add new function to record reserved
    space into delayed ref (bsc#963193).

  - btrfs: delayed_ref: release and free qgroup reserved at
    proper timing (bsc#963193).

  - btrfs: extent_io: Introduce needed structure for
    recoding set/clear bits (bsc#963193).

  - btrfs: extent_io: Introduce new function
    clear_record_extent_bits() (bsc#963193).

  - btrfs: extent_io: Introduce new function
    set_record_extent_bits (bsc#963193).

  - btrfs: extent-tree: Add new version of
    btrfs_check_data_free_space and
    btrfs_free_reserved_data_space (bsc#963193).

  - btrfs: extent-tree: Add new version of
    btrfs_delalloc_reserve/release_space (bsc#963193).

  - btrfs: extent-tree: Switch to new check_data_free_space
    and free_reserved_data_space (bsc#963193).

  - btrfs: extent-tree: Switch to new delalloc space reserve
    and release (bsc#963193).

  - btrfs: fallocate: Add support to accurate qgroup reserve
    (bsc#963193).

  - btrfs: fix invalid page accesses in extent_same (dedup)
    ioctl (bnc#968230).

  - btrfs: fix page reading in extent_same ioctl leading to
    csum errors (bnc#968230).

  - btrfs: fix warning in backref walking (bnc#966278).

  - btrfs: qgroup: Add handler for NOCOW and inline
    (bsc#963193).

  - btrfs: qgroup: Add new trace point for qgroup data
    reserve (bsc#963193).

  - btrfs: qgroup: Avoid calling
    btrfs_free_reserved_data_space in clear_bit_hook
    (bsc#963193).

  - btrfs: qgroup: Check if qgroup reserved space leaked
    (bsc#963193).

  - btrfs: qgroup: Cleanup old inaccurate facilities
    (bsc#963193).

  - btrfs: qgroup: Fix a race in delayed_ref which leads to
    abort trans (bsc#963193).

  - btrfs: qgroup: Fix a rebase bug which will cause qgroup
    double free (bsc#963193).

  - btrfs: qgroup: Fix dead judgement on
    qgroup_rescan_leaf() return value (bsc#969439).

  - btrfs: qgroup: Introduce btrfs_qgroup_reserve_data
    function (bsc#963193).

  - btrfs: qgroup: Introduce functions to release/free
    qgroup reserve data space (bsc#963193).

  - btrfs: qgroup: Introduce new functions to reserve/free
    metadata (bsc#963193).

  - btrfs: qgroup: Use new metadata reservation
    (bsc#963193).

  - cpu: Provide smpboot_thread_init() on !CONFIG_SMP
    kernels as well.

  - dcache: use IS_ROOT to decide where dentry is hashed
    (bsc#949752).

  - dmapi: fix dm_open_by_handle_rvp taking an extra ref to
    mnt (bsc#967292).

  - drivers/base/memory.c: fix kernel warning during memory
    hotplug on ppc64 (bsc#963827).

  - drivers:hv: Allow for MMIO claims that span ACPI _CRS
    records (bnc#965924).

  - drivers:hv: Define the channel type for Hyper-V PCI
    Express pass-through (bnc#965924).

  - drivers:hv: Export a function that maps Linux CPU num
    onto Hyper-V proc num (bnc#965924).

  - drivers:hv: Export the API to invoke a hypercall on
    Hyper-V (bnc#965924).

  - drivers: hv: kvp: fix IP Failover.

  - drivers:pci:hv: New paravirtual PCI front-end for
    Hyper-V VMs (bnc#965924).

  - drivers: xen-blkfront: only talk_to_blkback() when in
    XenbusStateInitialising (bsc#957986 fate#320625).

  - driver: xen-blkfront: move talk_to_blkback to a more
    suitable place (bsc#957986 fate#320625).

  - drm/i915: do not warn if backlight unexpectedly enabled
    (boo#972068).

  - drm/i915: set backlight duty cycle after backlight
    enable for gen4 (boo#972780).

  - e1000e: Avoid divide by zero error (bsc#968643).

  - e1000e: fix division by zero on jumbo MTUs (bsc#968643).

  - e1000e: Fix tight loop implementation of systime read
    algorithm (bsc#968643).

  - fix: print ext4 mountopt data_err=abort correctly
    (bsc#969735).

  - fs/proc_namespace.c: simplify testing nsp and
    nsp->mnt_ns (bug#963960).

  - futex: Drop refcount if requeue_pi() acquired the
    rtmutex (bug#960174).

  - hv: Lock access to hyperv_mmio resource tree
    (bnc#965924).

  - hv: Make a function to free mmio regions through vmbus
    (bnc#965924).

  - hv: Reverse order of resources in hyperv_mmio
    (bnc#965924).

  - hv: Track allocations of children of hv_vmbus in private
    resource tree (bnc#965924).

  - hv: Use new vmbus_mmio_free() from client drivers
    (bnc#965924).

  - hwmon: (coretemp) Increase maximum core to 128
    (bsc#970160)

  - ibmvnic: Fix ibmvnic_capability struct (fate#320253).

  - intel_pstate: Use del_timer_sync in
    intel_pstate_cpu_stop (bsc#967650).

  - ipv6: mld: fix add_grhead skb_over_panic for devs with
    large MTUs (bsc#956852).

  - kabi: Preserve checksum of kvm_x86_ops (bsc#969112).

  - kABI: protect enum enclosure_component_type.

  - kabi: protect struct acpi_processor signature
    (bsc#959463).

  - kABI: protect struct af_alg_type.

  - kABI: protect struct crypto_ahash.

  - kABI: protect struct dm_exception_store_type.

  - kABI: protect struct fib_nh_exception.

  - kABI: protect struct module.

  - kABI: protect struct rq.

  - kABI: protect struct sched_class.

  - kABI: protect struct scm_creds.

  - kABI: protect struct user_struct.

  - kabi/severities :

  - kabi/severities: Fail on changes in kvm_x86_ops, needed
    by lttng-modules

  - kgr: fix reversion of a patch already reverted by a
    replace_all patch (fate#313296).

  - kvm: SVM: add rdmsr support for AMD event registers
    (bsc#968448).

  - kvm: x86: Check dest_map->vector to match eoi signals
    for rtc (bsc#966471).

  - kvm: x86: Convert ioapic->rtc_status.dest_map to a
    struct (bsc#966471).

  - kvm: x86: store IOAPIC-handled vectors in each VCPU
    (bsc#966471).

  - kvm: x86: Track irq vectors in
    ioapic->rtc_status.dest_map (bsc#966471).

  - libceph: fix scatterlist last_piece calculation
    (bsc#963746).

  - lpfc: Fix kmalloc overflow in LPFC driver at large core
    count (bsc#969690).

  - memcg: do not hang on OOM when killed by userspace OOM
    access to memory reserves (bnc#969571).

  - mld, igmp: Fix reserved tailroom calculation
    (bsc#956852).

  - mmc: Exynos: Add module alias for dw mmc.

  - mvneta: fix per-cpu stats initialization.

  - namespaces: Re-introduce task_nsproxy() helper
    (bug#963960).

  - namespaces: Use task_lock and not rcu to protect nsproxy
    (bug#963960).

  - net: core: Correct an over-stringent device loop
    detection (bsc#945219).

  - net: irda: Fix use-after-free in irtty_open()
    (bnc#967903).

  - nfs4: treat lock owners as opaque values (bnc#968141).

  - nfs: Background flush should not be low priority
    (bsc#955308).

  - nfsd: fix nfsd_setattr return code for HSM (bsc#969992).

  - nfs: do not use STABLE writes during writeback
    (bnc#816099).

  - nfs: Fix handling of re-write-before-commit for mmapped
    NFS pages (bsc#964201).

  - nvme: default to 4k device page size (bsc#967047).

  - nvme: special case AEN requests (bsc#965087).

  - omap3isp: fix miscompile.

  - omap: Fix missing cm3xxx.h include.

  - omap: Fix missing usb.h include.

  - pci: Add global pci_lock_rescan_remove() (bnc#965924).

  - pci: allow access to VPD attributes with size 0
    (bsc#959146).

  - pciback: Check PF instead of VF for PCI_COMMAND_MEMORY.

  - pciback: Save the number of MSI-X entries to be copied
    later.

  - pci: Blacklist vpd access for buggy devices
    (bsc#959146).

  - pci: Determine actual VPD size on first access
    (bsc#959146).

  - pci: Export symbols required for loadable host driver
    modules (bnc#965924).

  - pci: pciehp: Disable link notification across slot reset
    (bsc#967651).

  - pci: pciehp: Do not check adapter or latch status while
    disabling (bsc#967651).

  - pci: pciehp: Do not disable the link permanently during
    removal (bsc#967651).

  - pci: pciehp: Ensure very fast hotplug events are also
    processed (bsc#967651).

  - pci: Update VPD definitions (bsc#959146).

  - perf, nmi: Fix unknown NMI warning (bsc#968512).

  - power: Add _GLOBAL_TOC for 32bit.

  - proc: Fix ptrace-based permission checks for accessing
    task maps.

  - qla2xxx: Remove unavailable firmware files (bsc#943645).

  - rbd: do not log miscompare as an error (bsc#970062).

  - Refresh
    patches.drivers/0005-aacraid-MSI-x-support.patch.
    (boo#970249)

  - resources: Set type in __request_region() (bnc#965924).

  - Revert 'ipv6: tcp: add rcu locking in
    tcp_v6_send_synack()' (bnc#961257).

  - rpm/kernel-binary.spec.in: Sync the main and -base
    package dependencies (bsc#965830#c51).

  - rpm/kernel-module-subpackage: Fix obsoleting dropped
    flavors (bsc#968253)

  - sched: unbreak non-SMP build.

  - scsi_dh_alua: Do not block request queue if workqueue is
    active (bsc#960458).

  - scsi: fix soft lockup in scsi_remove_target() on module
    removal (bsc#965199).

  - scsi: proper state checking and module refcount handling
    in scsi_device_get (boo#966831).

  - series.conf: add section comments

  - supported.conf: Add e1000e (emulated by VMware) to -base
    (bsc#968074)

  - supported.conf: Add Hyper-V modules to -base
    (bsc#965830)

  - supported.conf: Add isofs to -base (bsc#969655).

  - supported.conf: Add more qemu device driver (bsc#968234)

  - supported.conf: Add mptspi and mptsas to -base
    (bsc#968206)

  - supported.conf: Add the qemu scsi driver (sym53c8xx) to
    -base (bsc#967802)

  - supported.conf: Add tulip to -base for Hyper-V
    (bsc#968234)

  - supported.conf: Add virtio-rng (bsc#966026)

  - supported.conf: Add xen-blkfront.

  - supported.conf: Add xfs to -base (bsc#965891)

  - supported.conf: Fix usb-common path usb-common moved to
    its own subdirectory in kernel v3.16, and we backported
    that change to SLE12.

  - sysctl: do not add hardlockup_all_cpu_backtrace sysctl
    on UP.

  - tcp: Restore RFC5961-compliant behavior for SYN packets
    (bsc#966864).

  - Update config files. Add new option
    CONFIG_PARAVIRT_XEN_BLKDEV_FRONTEND to i386 xen and ec2.

  - Update config files. Enable CONFIG_DEBUG_INFO for ec2
    flavor. It's overriden on build anyway and having it
    disabled causes 'make silentoldconfig' checks fail
    because of new symbol CONFIG_DEBUG_INFO_REDUCED.

  - Update config files: enable CONFIG_PCI_HYPERV in non-SLE
    configs These are i386/* except xen, ec2 and vanilla and
    x86_64 desktop and trace.

  - Update config files: enable MACH_CUBOX in armv7hl/cubox

  - Update config files: ppc and ppc64 are big endian New
    config options (not existing in 13.1) need to be set
    accordingly.

  - Update
    patches.drivers/drm-ast-Initialize-data-needed-to-map-fb
    dev-memory.patch (bnc#880007). Fix refs and upstream
    status.

  - Update Xen config files (enable upstream block
    frontend).

  - Update Xen patches to 3.12.55.

  - USB: ehci-s5p: Fix phy reset.

  - usb: phy: Fix phy-samsung-usb when built as module.

  - usb: Quiet down false peer failure messages
    (bnc#960629).

  - x86: export x86_msi (bnc#965924).

  - xen: Add /etc/modprobe.d/50-xen.conf selecting Xen
    frontend driver implementation (bsc#957986, bsc#956084,
    bsc#961658).

  - xen-blkfront: allow building in our Xen environment
    (bsc#957986 fate#320625).

  - xen, blkfront: factor out flush-related checks from
    do_blkif_request() (bsc#957986 fate#320625).

  - xen-blkfront: fix accounting of reqs when migrating
    (bsc#957986 fate#320625).

  - xen/blkfront: Fix crash if backend does not follow the
    right states (bsc#957986 fate#320625).

  - xen-blkfront: improve aproximation of required grants
    per request (bsc#957986 fate#320625).

  - xen/blkfront: improve protection against issuing
    unsupported REQ_FUA (bsc#957986 fate#320625).

  - xen/blkfront: remove redundant flush_op (bsc#957986
    fate#320625).

  - xen-blkfront: remove type check from
    blkfront_setup_discard (bsc#957986 fate#320625).

  - xen-blkfront: Silence pfn maybe-uninitialized warning
    (bsc#957986 fate#320625).

  - xen: fix blkfront and blkback build with normal xen.

  - xen-vscsi-large-requests: Fix resource collision for
    racing request maps and unmaps (bsc#966094).

  - xfs/dmapi: drop lock over synchronous XFS_SEND_DATA
    events (bsc#969993).

  - xfs/dmapi: propertly send postcreate event (bsc#967299)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=816099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=867251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=880007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=956852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960563"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=965924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972780"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vhba-kmp-xen-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-host-source");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE13.1", reference:"cloop-2.639-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debuginfo-2.639-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-debugsource-2.639-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-default-debuginfo-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-pae-debuginfo-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"cloop-kmp-xen-debuginfo-2.639_k3.12.57_44-11.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debuginfo-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-debugsource-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-devel-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-eppic-debuginfo-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-gcore-debuginfo-7.0.2-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-default-debuginfo-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-desktop-debuginfo-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-pae-debuginfo-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"crash-kmp-xen-debuginfo-7.0.2_k3.12.57_44-2.28.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-debugsource-1.28-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.12.57_44-16.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-6.21.1-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debuginfo-6.21.1-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-debugsource-6.21.1-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-devel-6.21.1-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-default-debuginfo-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-desktop-debuginfo-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-pae-debuginfo-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ipset-kmp-xen-debuginfo-6.21.1_k3.12.57_44-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-1.4.20.3-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debuginfo-1.4.20.3-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-debugsource-1.4.20.3-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-default-debuginfo-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-desktop-debuginfo-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-pae-debuginfo-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"iscsitarget-kmp-xen-debuginfo-1.4.20.3_k3.12.57_44-13.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-devel-3.12.57-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-macros-3.12.57-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-3.12.57-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-vanilla-3.12.57-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-syms-3.12.57-44.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-6.21.1-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"libipset3-debuginfo-6.21.1-2.32.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-1.58-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debuginfo-1.58-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-debugsource-1.58-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-1.58_k3.12.57_44-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-default-debuginfo-1.58_k3.12.57_44-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-1.58_k3.12.57_44-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-desktop-debuginfo-1.58_k3.12.57_44-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-1.58_k3.12.57_44-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"ndiswrapper-kmp-pae-debuginfo-1.58_k3.12.57_44-29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-controller-debuginfo-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debuginfo-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-debugsource-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-default-debuginfo-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-desktop-debuginfo-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-pae-debuginfo-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-kmp-xen-debuginfo-1.11.0_k3.12.57_44-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-pki-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-switch-debuginfo-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"openvswitch-test-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-0.44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debuginfo-0.44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-debugsource-0.44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-0.44_k3.12.57_44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.12.57_44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-0.44_k3.12.57_44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.12.57_44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-0.44_k3.12.57_44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.12.57_44-258.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-openvswitch-test-1.11.0-0.35.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"python-virtualbox-debuginfo-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-debugsource-20130607-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-default-debuginfo-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-desktop-debuginfo-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-pae-debuginfo-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"vhba-kmp-xen-debuginfo-20130607_k3.12.57_44-2.28.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debuginfo-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-debugsource-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-devel-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-default-debuginfo-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-kmp-pae-debuginfo-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-tools-debuginfo-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-guest-x11-debuginfo-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-default-debuginfo-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-desktop-debuginfo-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-kmp-pae-debuginfo-4.2.36_k3.12.57_44-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-host-source-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-qt-debuginfo-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"virtualbox-websrv-debuginfo-4.2.36-2.60.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-debugsource-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-devel-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-4.3.4_10_k3.12.57_44-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-default-debuginfo-4.3.4_10_k3.12.57_44-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-4.3.4_10_k3.12.57_44-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-desktop-debuginfo-4.3.4_10_k3.12.57_44-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-4.3.4_10_k3.12.57_44-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-kmp-pae-debuginfo-4.3.4_10_k3.12.57_44-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-libs-debuginfo-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xen-tools-domU-debuginfo-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-2.3-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debuginfo-2.3-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-debugsource-2.3-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-default-debuginfo-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-desktop-debuginfo-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-pae-debuginfo-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xtables-addons-kmp-xen-debuginfo-2.3_k3.12.57_44-2.27.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.57-44.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-doc-html-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-32bit-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-tools-debuginfo-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-4.3.4_10-61.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"xen-xend-tools-debuginfo-4.3.4_10-61.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cloop / cloop-debuginfo / cloop-debugsource / cloop-kmp-default / etc");
}
