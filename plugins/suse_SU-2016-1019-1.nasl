#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1019-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(90531);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2015-8709", "CVE-2015-8812", "CVE-2015-8816", "CVE-2016-2143", "CVE-2016-2184", "CVE-2016-2384", "CVE-2016-2782", "CVE-2016-3139", "CVE-2016-3156");
  script_osvdb_id(132475, 134512, 134538, 134938, 135143, 135875, 135877, 135943, 135975);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:1019-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP1 kernel was updated to 3.12.57 to
receive various security and bugfixes.

The following security bugs were fixed :

  - CVE-2015-8812: A flaw was found in the CXGB3 kernel
    driver when the network was considered congested. The
    kernel would incorrectly misinterpret the congestion as
    an error condition and incorrectly free/clean up the
    skb. When the device would then send the skb's queued,
    these structures would be referenced and may panic the
    system or allow an attacker to escalate privileges in a
    use-after-free scenario. (bsc#966437)

  - CVE-2015-8816: A malicious USB device could cause a
    kernel crash in the USB hub driver. (bnc#968010).

  - CVE-2016-2143: On zSeries a fork of a large process
    could have caused memory corruption due to incorrect
    page table handling. (bnc#970504)

  - CVE-2016-2184: A malicious USB device could cause a
    kernel crash in the alsa usb-audio driver. (bsc#971125).

  - CVE-2016-2384: A malicious USB device could cause a
    kernel crash in the alsa usb-audio driver. (bsc#966693)

  - CVE-2016-2782: A malicious USB device could cause a
    kernel crash in the usb visor driver. (bnc#968670).

  - CVE-2016-3139: A malicious USB device could cause a
    kernel crash in the wacom driver. (bnc#970909).

  - CVE-2016-3156: Removal of ipv4 interfaces with a large
    number of IP addresses was taking very long.
    (bsc#971360).

  - CVE-2015-8709: kernel/ptrace.c in the Linux kernel
    mishandled uid and gid mappings, which allowed local
    users to gain privileges by establishing a user
    namespace, waiting for a root process to enter that
    namespace with an unsafe uid or gid, and then using the
    ptrace system call. NOTE: the vendor states 'there is no
    kernel bug here (bnc#960561).

The following non-security bugs were fixed :

  - aacraid: Refresh
    patches.drivers/0005-aacraid-MSI-x-support.patch.
    (boo#970249)

  - acpi: processor: Introduce apic_id in struct processor
    to save parsed APIC id (bsc#959463).

  - alsa: rawmidi: Make snd_rawmidi_transmit() race-free
    (bsc#968018).

  - alsa: seq: Fix leak of pool buffer at concurrent writes
    (bsc#968018).

  - btrfs: Account data space in more proper timing:
    (bsc#963193).

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

  - btrfs: fallocate: Added a prerequisite patch and rebased
    the chunks that had previously been taken from it. Fixes
    a warning we had in fs/btrfs/file.c.

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

  - dcache: use IS_ROOT to decide where dentry is hashed
    (bsc#949752).

  - dmapi: fix dm_open_by_handle_rvp taking an extra ref to
    mnt (bsc#967292).

  - drivers/base/memory.c: fix kernel warning during memory
    hotplug on ppc64 (bsc#963827).

  - drivers: hv: Allow for MMIO claims that span ACPI _CRS
    records (bnc#965924).

  - drivers: hv: Define the channel type for Hyper-V PCI
    Express pass-through (bnc#965924).

  - drivers: hv: Export a function that maps Linux CPU num
    onto Hyper-V proc num (bnc#965924).

  - drivers: hv: Export the API to invoke a hypercall on
    Hyper-V (bnc#965924).

  - drivers: hv: kvp: fix IP Failover.

  - drivers: pci:hv: New paravirtual PCI front-end for
    Hyper-V VMs (bnc#965924).

  - drivers: xen-blkfront: only talk_to_blkback() when in
    XenbusStateInitialising (bsc#957986 fate#320625).

  - drivers: xen-blkfront: move talk_to_blkback to a more
    suitable place (bsc#957986 fate#320625).

  - e1000e: Avoid divide by zero error (bsc#968643).

  - e1000e: fix division by zero on jumbo MTUs (bsc#968643).

  - e1000e: Fix tight loop implementation of systime read
    algorithm (bsc#968643).

  - efi: Ignore efivar_validate kabi failures -- it's an EFI
    internal function.

  - fix: print ext4 mountopt data_err=abort correctly
    (bsc#969735).

  - Fix problem with setting ACL on directories
    (bsc#867251).

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

  - kabi: protect struct acpi_processor signature
    (bsc#959463).

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

  - libata: Revert 'libata: Align ata_device's id on a
    cacheline'.

  - libceph: fix scatterlist last_piece calculation
    (bsc#963746).

  - lpfc: Fix kmalloc overflow in LPFC driver at large core
    count (bsc#969690).

  - memcg: do not hang on OOM when killed by userspace OOM
    access to memory reserves (bnc#969571).

  - mld, igmp: Fix reserved tailroom calculation
    (bsc#956852).

  - namespaces: Re-introduce task_nsproxy() helper
    (bug#963960).

  - namespaces: Use task_lock and not rcu to protect nsproxy
    (bug#963960).

  - net: core: Correct an over-stringent device loop
    detection (bsc#945219).

  - net: irda: Fix use-after-free in irtty_open()
    (bnc#967903).

  - net: Revert 'net/ipv6: add sysctl option
    accept_ra_min_hop_limit'.

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

  - proc: Fix ptrace-based permission checks for accessing
    task maps.

  - pv6: Revert 'ipv6: tcp: add rcu locking in
    tcp_v6_send_synack()' (bnc#961257).

  - qla2xxx: Remove unavailable firmware files (bsc#943645).

  - rbd: do not log miscompare as an error (bsc#970062).

  - resources: Set type in __request_region() (bnc#965924).

  - rpm/kernel-binary.spec.in: Sync the main and -base
    package dependencies (bsc#965830#c51).

  - rpm/kernel-module-subpackage: Fix obsoleting dropped
    flavors (bsc#968253)

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

  - tcp: Restore RFC5961-compliant behavior for SYN packets
    (bsc#966864).

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

  - xen: block: xen-blkfront: Fix possible NULL ptr
    dereference (bsc#957986 fate#320625).

  - xen: Refresh patches.xen/xen3-patch-2.6.33 (detect NX
    support early).

  - xen: Refresh patches.xen/xen-vscsi-large-requests
    (gsc#966094).

  - xen: Update Xen config files (enable upstream block
    frontend).

  - xen: Update Xen patches to 3.12.55.

  - xen-vscsi-large-requests: Fix resource collision for
    racing request maps and unmaps (bsc#966094).

  - xfs/dmapi: drop lock over synchronous XFS_SEND_DATA
    events (bsc#969993).

  - xfs/dmapi: propertly send postcreate event (bsc#967299).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/816099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/875631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/880007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/955308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959146"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961516"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967650"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/967903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969571"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969735"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8816.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2143.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2384.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2782.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3156.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161019-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1da0184d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP1 :

zypper in -t patch SUSE-SLE-WE-12-SP1-2016-600=1

SUSE Linux Enterprise Software Development Kit 12-SP1 :

zypper in -t patch SUSE-SLE-SDK-12-SP1-2016-600=1

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-600=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2016-600=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2016-600=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-600=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", cpu:"s390x", reference:"kernel-default-man-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-base-debuginfo-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debuginfo-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-debugsource-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-default-devel-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"kernel-syms-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-devel-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-syms-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.57-60.35.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"kernel-xen-devel-3.12.57-60.35.1")) flag++;


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
