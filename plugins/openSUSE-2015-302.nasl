#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-302.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(82756);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/23 13:29:51 $");

  script_cve_id("CVE-2014-8134", "CVE-2014-8160", "CVE-2014-8559", "CVE-2014-9419", "CVE-2014-9420", "CVE-2014-9428", "CVE-2014-9529", "CVE-2014-9584", "CVE-2014-9585", "CVE-2014-9683", "CVE-2015-0275", "CVE-2015-0777", "CVE-2015-1421", "CVE-2015-1593", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2666", "CVE-2015-2830");

  script_name(english:"openSUSE Security Update : Linux Kernel (openSUSE-2015-302)");
  script_summary(english:"Check for the openSUSE-2015-302 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux kernel was updated to fix bugs and security issues :

Following security issues were fixed: CVE-2015-2830: A flaw was found
in the way the Linux kernels 32-bit emulation implementation handled
forking or closing of a task with an int80 entry. A local user could
have potentially used this flaw to escalate their privileges on the
system.

CVE-2015-2042: A kernel information leak in rds sysctl files was
fixed.

CVE-2014-9683: Off-by-one error in the ecryptfs_decode_from_filename
function in fs/ecryptfs/crypto.c in the eCryptfs subsystem in the
Linux kernel allowed local users to cause a denial of service (buffer
overflow and system crash) or possibly gain privileges via a crafted
filename.

CVE-2015-0275: A BUG_ON in ext4 was fixed which could be triggered by
local users.

CVE-2015-2666: A buffer overflow when loading microcode files into the
kernel could be used by the administrator to execute code in the
kernel, bypassing secure boot measures.

  - CVE-2015-1421: Use-after-free vulnerability in the
    sctp_assoc_update function in net/sctp/associola.c in
    the Linux kernel allowed remote attackers to cause a
    denial of service (slab corruption and panic) or
    possibly have unspecified other impact by triggering an
    INIT collision that leads to improper handling of
    shared-key data.

  - CVE-2015-2150: XSA-120: Guests were permitted to modify
    all bits of the PCI command register of passed through
    cards, which could lead to Host system crashes.

  - CVE-2015-0777: The XEN usb backend could leak
    information to the guest system due to copying
    uninitialized memory.

  - CVE-2015-1593: A integer overflow reduced the
    effectiveness of the stack randomization on 64-bit
    systems.

  - CVE-2014-9419: The __switch_to function in
    arch/x86/kernel/process_64.c in the Linux kernel did not
    ensure that Thread Local Storage (TLS) descriptors are
    loaded before proceeding with other steps, which made it
    easier for local users to bypass the ASLR protection
    mechanism via a crafted application that reads a TLS
    base address.

  - CVE-2014-9428: The batadv_frag_merge_packets function in
    net/batman-adv/fragmentation.c in the B.A.T.M.A.N.
    implementation in the Linux kernel used an incorrect
    length field during a calculation of an amount of
    memory, which allowed remote attackers to cause a denial
    of service (mesh-node system crash) via fragmented
    packets.

  - CVE-2014-8160:
    net/netfilter/nf_conntrack_proto_generic.c in the Linux
    kernel generated incorrect conntrack entries during
    handling of certain iptables rule sets for the SCTP,
    DCCP, GRE, and UDP-Lite protocols, which allowed remote
    attackers to bypass intended access restrictions via
    packets with disallowed port numbers.

  - CVE-2014-9529: Race condition in the key_gc_unused_keys
    function in security/keys/gc.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption or panic) or possibly have unspecified other
    impact via keyctl commands that trigger access to a key
    structure member during garbage collection of a key.

  - CVE-2014-9420: The rock_continue function in
    fs/isofs/rock.c in the Linux kernel did not restrict the
    number of Rock Ridge continuation entries, which allowed
    local users to cause a denial of service (infinite loop,
    and system crash or hang) via a crafted iso9660 image.

  - CVE-2014-9584: The parse_rock_ridge_inode_internal
    function in fs/isofs/rock.c in the Linux kernel did not
    validate a length value in the Extensions Reference (ER)
    System Use Field, which allowed local users to obtain
    sensitive information from kernel memory via a crafted
    iso9660 image.

  - CVE-2014-9585: The vdso_addr function in
    arch/x86/vdso/vma.c in the Linux kernel did not properly
    choose memory locations for the vDSO area, which made it
    easier for local users to bypass the ASLR protection
    mechanism by guessing a location at the end of a PMD.

  - CVE-2014-8559: The d_walk function in fs/dcache.c in the
    Linux kernel through did not properly maintain the
    semantics of rename_lock, which allowed local users to
    cause a denial of service (deadlock and system hang) via
    a crafted application.

  - CVE-2014-8134: The paravirt_ops_setup function in
    arch/x86/kernel/kvm.c in the Linux kernel used an
    improper paravirt_enabled setting for KVM guest kernels,
    which made it easier for guest OS users to bypass the
    ASLR protection mechanism via a crafted application that
    reads a 16-bit value.

Following bugs were fixed :

  - powerpc/pci: Fix IO space breakage after
    of_pci_range_to_resource() change (bnc#922542).

  - cifs: fix use-after-free bug in find_writable_file
    (bnc#909477).

  - usb: Do not allow usb_alloc_streams on unconfigured
    devices (bsc#920581).

  - fuse: honour max_read and max_write in direct_io mode
    (bnc#918954).

  - switch iov_iter_get_pages() to passing maximal number of
    pages (bnc#918954).

  - bcache: fix a livelock in btree lock v2 (bnc#910440)
    (bnc#910440). Updated because another version went
    upstream

  - drm/i915: Initialise userptr mmu_notifier serial to 1
    (bnc#918970).

  - NFS: Don't try to reclaim delegation open state if
    recovery failed (boo#909634).

  - NFSv4: Ensure that we call FREE_STATEID when NFSv4.x
    stateids are revoked (boo#909634).

  - NFSv4: Fix races between nfs_remove_bad_delegation() and
    delegation return (boo#909634).

  - NFSv4: Ensure that we remove NFSv4.0 delegations when
    state has expired (boo#909634).

  - Fixing lease renewal (boo#909634).

  - bcache: Fix a bug when detaching (bsc#908582).

  - fix a leak in bch_cached_dev_run() (bnc#910440).

  - bcache: unregister reboot notifier when bcache fails to
    register a block device (bnc#910440).

  - bcache: fix a livelock in btree lock (bnc#910440).

  - bcache: [BUG] clear BCACHE_DEV_UNLINK_DONE flag when
    attaching a backing device (bnc#910440).

  - bcache: Add a cond_resched() call to gc (bnc#910440).

  - storvsc: ring buffer failures may result in I/O freeze
    (bnc#914175).

  - ALSA: seq-dummy: remove deadlock-causing events on close
    (boo#916608).

  - ALSA: pcm: Zero-clear reserved fields of PCM status
    ioctl in compat mode (boo#916608).

  - ALSA: bebob: Uninitialized id returned by
    saffirepro_both_clk_src_get (boo#916608).

  - ALSA: hda - Fix built-in mic on Compaq Presario CQ60
    (bnc#920604).

  - ALSA: hda - Fix regression of HD-audio controller
    fallback modes (bsc#921313).

  - [media] sound: Update au0828 quirks table (boo#916608).

  - [media] sound: simplify au0828 quirk table (boo#916608).

  - ALSA: usb-audio: Add mic volume fix quirk for Logitech
    Webcam C210 (boo#916608).

  - ALSA: usb-audio: extend KEF X300A FU 10 tweak to Arcam
    rPAC (boo#916608).

  - ALSA: usb-audio: Add ctrl message delay quirk for
    Marantz/Denon devices (boo#916608).

  - ALSA: usb-audio: Fix memory leak in FTU quirk
    (boo#916608).

  - ALSA: usb-audio: Fix device_del() sysfs warnings at
    disconnect (boo#916608).

  - ALSA: hda - Add new GPU codec ID 0x10de0072 to snd-hda
    (boo#916608).

  - ALSA: hda - Fix wrong gpio_dir & gpio_mask hint setups
    for IDT/STAC codecs (boo#916608).

  - ALSA: hda/realtek - New codec support for ALC298
    (boo#916608).

  - ALSA: hda/realtek - New codec support for ALC256
    (boo#916608).

  - ALSA: hda/realtek - Add new Dell desktop for ALC3234
    headset mode (boo#916608).

  - ALSA: hda - Add EAPD fixup for ASUS Z99He laptop
    (boo#916608).

  - ALSA: hda - Fix built-in mic at resume on Lenovo Ideapad
    S210 (boo#916608).

  - ALSA: hda/realtek - Add headset Mic support for new Dell
    machine (boo#916608).

  - ALSA: hda_intel: Add DeviceIDs for Sunrise Point-LP
    (boo#916608).

  - ALSA: hda_intel: Add Device IDs for Intel Sunrise Point
    PCH (boo#916608).

  - ALSA: hda - add codec ID for Braswell display audio
    codec (boo#916608).

  - ALSA: hda - add PCI IDs for Intel Braswell (boo#916608).

  - ALSA: hda - Add dock support for Thinkpad T440
    (17aa:2212) (boo#916608).

  - ALSA: hda - Set up GPIO for Toshiba Satellite S50D
    (bnc#915858).

  - rpm/kernel-binary.spec.in: Fix build if there is no
    *.crt file

  - mm, vmscan: prevent kswapd livelock due to
    pfmemalloc-throttled process being killed (VM
    Functionality bnc#910150).

  - Input: evdev - fix EVIOCG{type} ioctl (bnc#904899).

  - mnt: Implicitly add MNT_NODEV on remount when it was
    implicitly added by mount (bsc#907988).

  - Btrfs: fix scrub race leading to use-after-free
    (bnc#915456).

  - Btrfs: fix setup_leaf_for_split() to avoid leaf
    corruption (bnc#915454).

  - Btrfs: fix fsync log replay for inodes with a mix of
    regular refs and extrefs (bnc#915425).

  - Btrfs: fix fsync when extend references are added to an
    inode (bnc#915425).

  - Btrfs: fix directory inconsistency after fsync log
    replay (bnc#915425).

  - Btrfs: make xattr replace operations atomic
    (bnc#913466).

  - Btrfs: fix directory recovery from fsync log
    (bnc#895797).

  - Btrfs: simplify insert_orphan_item (boo#926385).

  - Btrfs: set proper message level for skinny metadata.

  - Btrfs: make sure we wait on logged extents when fsycning
    two subvols.

  - Btrfs: fix lost return value due to variable shadowing.

  - Btrfs: fix leak of path in btrfs_find_item.

  - Btrfs: fix fsync data loss after adding hard link to
    inode.

  - Btrfs: fix fs corruption on transaction abort if device
    supports discard.

  - Btrfs: fix data loss in the fast fsync path.

  - Btrfs: don't delay inode ref updates during log replay.

  - Btrfs: do not move em to modified list when unpinning.

  - Btrfs:__add_inode_ref: out of bounds memory read when
    looking for extended ref.

  - Btrfs: fix inode eviction infinite loop after cloning
    into it (boo#905088).

  - bcache: add mutex lock for bch_is_open (bnc#908612).

  - bcache: Correct printing of btree_gc_max_duration_ms
    (bnc#908610).

  - bcache: fix crash with incomplete cache set
    (bnc#908608).

  - bcache: fix memory corruption in init error path
    (bnc#908606).

  - bcache: Fix more early shutdown bugs (bnc#908605).

  - bcache: fix use-after-free in btree_gc_coalesce()
    (bnc#908604).

  - bcache: Fix an infinite loop in journal replay
    (bnc#908603).

  - bcache: fix typo in bch_bkey_equal_header (bnc#908598).

  - bcache: Make sure to pass GFP_WAIT to mempool_alloc()
    (bnc#908596).

  - bcache: fix crash on shutdown in passthrough mode
    (bnc#908594).

  - bcache: fix lockdep warnings on shutdown (bnc#908593).

  - bcache allocator: send discards with correct size
    (bnc#908592).

  - bcache: Fix to remove the rcu_sched stalls (bnc#908589).

  - bcache: Fix a journal replay bug (bnc#908588).

  - Update x86_64 config files: CONFIG_SENSORS_NCT6683=m The
    nct6683 driver is already enabled on i386 and history
    suggests that it not being enabled on x86_64 is by
    mistake.

  - rpm/kernel-binary.spec.in: Own the modules directory in
    the devel package (bnc#910322)

  - Revert 'iwlwifi: mvm: treat EAPOLs like mgmt frames wrt
    rate' (bnc#900811).

  - mm: free compound page with correct order (bnc#913695).

  - drm/i915: More cautious with pch fifo underruns
    (boo#907039).

  - Refresh patches.arch/arm64-0039-generic-pci.patch (fix
    PCI bridge support)

  - x86/microcode/intel: Fish out the stashed microcode for
    the BSP (bsc#903589).

  - x86, microcode: Reload microcode on resume (bsc#903589).

  - x86, microcode: Don't initialize microcode code on
    paravirt (bsc#903589).

  - x86, microcode, intel: Drop unused parameter
    (bsc#903589).

  - x86, microcode, AMD: Do not use smp_processor_id() in
    preemtible context (bsc#903589).

  - x86, microcode: Update BSPs microcode on resume
    (bsc#903589).

  - x86, microcode, AMD: Fix ucode patch stashing on 32-bit
    (bsc#903589).

  - x86, microcode: Fix accessing dis_ucode_ldr on 32-bit
    (bsc#903589).

  - x86, microcode, AMD: Fix early ucode loading on 32-bit
    (bsc#903589).

  - Bluetooth: Add support for Broadcom BCM20702A0 variants
    firmware download (bnc#911311).

  - drm/radeon: fix sad_count check for dce3 (bnc#911356).

  - drm/i915: Don't call intel_prepare_page_flip() multiple
    times on gen2-4 (bnc#911835).

  - udf: Check component length before reading it.

  - udf: Check path length when reading symlink.

  - udf: Verify symlink size before loading it.

  - udf: Verify i_size when loading inode.

  - arm64: Enable DRM

  - arm64: Enable generic PHB driver (bnc#912061).

  - ACPI / video: Add some Samsung models to
    disable_native_backlight list (boo#905681).

  - asus-nb-wmi: Add another wapf=4 quirk (boo#911438).

  - asus-nb-wmi: Add wapf4 quirk for the X550VB
    (boo#911438).

  - asus-nb-wmi: Add wapf4 quirk for the U32U (boo#911438).

  - asus-nb-wmi: Add wapf4 quirk for the X550CC
    (boo#911438).

  - asus-nb-wmi: Constify asus_quirks DMI table
    (boo#911438).

  - asus-nb-wmi: Add wapf4 quirk for the X550CL
    (boo#911438).

  - asus-nb-wmi.c: Rename x401u quirk to wapf4 (boo#911438).

  - asus-nb-wmi: Add ASUSTeK COMPUTER INC. X200CA
    (boo#911438).

  - WAPF 4 for ASUSTeK COMPUTER INC. X75VBP WLAN ON
    (boo#911438).

  - Input: synaptics - gate forcepad support by DMI check
    (bnc#911578).

  - ext4: introduce aging to extent status tree
    (bnc#893428).

  - ext4: cleanup flag definitions for extent status tree
    (bnc#893428).

  - ext4: limit number of scanned extents in status tree
    shrinker (bnc#893428).

  - ext4: move handling of list of shrinkable inodes into
    extent status code (bnc#893428).

  - ext4: change LRU to round-robin in extent status tree
    shrinker (bnc#893428).

  - ext4: cache extent hole in extent status tree for
    ext4_da_map_blocks() (bnc#893428).

  - ext4: fix block reservation for bigalloc filesystems
    (bnc#893428).

  - ext4: track extent status tree shrinker delay statictics
    (bnc#893428).

  - ext4: improve extents status tree trace point
    (bnc#893428).

  - rpm/kernel-binary.spec.in: Provide name-version-release
    for kgraft packages (bnc#901925)

  - rpm/kernel-binary.spec.in: Fix including the secure boot
    cert in /etc/uefi/certs

  - doc/README.SUSE: update Solid Driver team contacts

  - rpm/kernel-binary.spec.in: Do not sign firmware files
    (bnc#867199)

  - Port module signing changes from SLE11-SP3 (fate#314508)

  - doc/README.PATCH-POLICY.SUSE: add patch policy / best
    practices document after installation.

  - Update config files. (boo#925479) Do not set
    CONFIG_SYSTEM_TRUSTED_KEYRING until we need it in future
    openSUSE version: e.g. MODULE_SIG, IMA, PKCS7(new),
    KEXEC_BZIMAGE_VERIFY_SIG(new)

  - Input: xpad - use proper endpoint type (bnc#926397).

  - md: don't require sync_min to be a multiple of
    chunk_size (bnc#910500)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=867199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=893428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=895797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900811"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=901925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=903640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=904899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=905681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908594"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908610"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=909634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=911835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912061"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912202"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=912705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=913059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=913466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=913695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=915858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=916608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=917839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=918970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=920604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=921313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=922944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=925479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=926397"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=927018"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:bbswitch-kmp-xen-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-guest-desktop-icons");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-0.8-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-debugsource-0.8-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-debuginfo-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-debuginfo-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-debuginfo-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-debuginfo-0.8_k3.16.7_21-3.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-2.639-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debuginfo-2.639-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debugsource-2.639-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-debuginfo-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-debuginfo-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-debuginfo-2.639_k3.16.7_21-14.9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debuginfo-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debugsource-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-devel-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-debuginfo-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-debuginfo-7.0.8-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-debuginfo-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-debuginfo-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-debuginfo-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-debuginfo-7.0.8_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-debugsource-1.28-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.16.7_21-18.10.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-6.23-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debuginfo-6.23-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debugsource-6.23-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-devel-6.23-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-debuginfo-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-debuginfo-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-debuginfo-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-debuginfo-6.23_k3.16.7_21-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-macros-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-3.16.7-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-debugsource-3.16.7-21.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-xen-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-vanilla-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-syms-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-6.23-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-debuginfo-6.23-9.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-0.44-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debuginfo-0.44-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debugsource-0.44-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-0.44_k3.16.7_21-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.16.7_21-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-0.44_k3.16.7_21-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.16.7_21-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-0.44_k3.16.7_21-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.16.7_21-260.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-debugsource-20140629-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-debuginfo-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-debuginfo-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-debuginfo-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-debuginfo-20140629_k3.16.7_21-2.9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-4.3.20_k3.16.7_21-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-4.3.20-13.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-debugsource-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-devel-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-debuginfo-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-debuginfo-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-2.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debuginfo-2.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debugsource-2.6-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-debuginfo-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-debuginfo-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-debuginfo-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-debuginfo-2.6_k3.16.7_21-9.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-devel-3.16.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-doc-html-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-4.4.1_08_k3.16.7_21-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.1_08_k3.16.7_21-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-4.4.1_08_k3.16.7_21-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-debuginfo-4.4.1_08_k3.16.7_21-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-32bit-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-4.4.1_08-15.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.1_08-15.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bbswitch / bbswitch-debugsource / bbswitch-kmp-default / etc");
}
