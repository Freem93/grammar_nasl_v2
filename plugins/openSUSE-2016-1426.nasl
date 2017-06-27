#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1426.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95701);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2015-1350", "CVE-2015-8964", "CVE-2016-7039", "CVE-2016-7042", "CVE-2016-7913", "CVE-2016-7917", "CVE-2016-8632", "CVE-2016-8655", "CVE-2016-8666", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9555", "CVE-2016-9794");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-1426)");
  script_summary(english:"Check for the openSUSE-2016-1426 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE Leap 42.2 kernel was updated to 4.4.36 to receive various
security and bugfixes.

The following security bugs were fixed :

  - CVE-2015-1350: The VFS subsystem in the Linux kernel 3.x
    provides an incomplete set of requirements for setattr
    operations that underspecifies removing extended
    privilege attributes, which allowed local users to cause
    a denial of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program (bnc#914939).

  - CVE-2015-8964: The tty_set_termios_ldisc function in
    drivers/tty/tty_ldisc.c in the Linux kernel allowed
    local users to obtain sensitive information from kernel
    memory by reading a tty data structure (bnc#1010507).

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux kernel through 4.8.2,
    when the GNU Compiler Collection (gcc) stack protector
    is enabled, uses an incorrect buffer size for certain
    timeout data, which allowed local users to cause a
    denial of service (stack memory corruption and panic) by
    reading the /proc/keys file (bnc#1004517).

  - CVE-2016-7913: The xc2028_set_config function in
    drivers/media/tuners/tuner-xc2028.c in the Linux kernel
    allowed local users to gain privileges or cause a denial
    of service (use-after-free) via vectors involving
    omission of the firmware name from a certain data
    structure (bnc#1010478).

  - CVE-2016-7917: The nfnetlink_rcv_batch function in
    net/netfilter/nfnetlink.c in the Linux kernel did not
    check whether a batch message's length field is large
    enough, which allowed local users to obtain sensitive
    information from kernel memory or cause a denial of
    service (infinite loop or out-of-bounds read) by
    leveraging the CAP_NET_ADMIN capability (bnc#1010444).

  - CVE-2016-8632: The tipc_msg_build function in
    net/tipc/msg.c in the Linux kernel did not validate the
    relationship between the minimum fragment length and the
    maximum packet size, which allowed local users to gain
    privileges or cause a denial of service (heap-based
    buffer overflow) by leveraging the CAP_NET_ADMIN
    capability (bnc#1008831).

  - CVE-2016-8655: A race condition in the af_packet
    packet_set_ring function could be used by local
    attackers to crash the kernel or gain privileges
    (bsc#1012754).

  - CVE-2016-8666: The IP stack in the Linux kernel allowed
    remote attackers to cause a denial of service (stack
    consumption and panic) or possibly have unspecified
    other impact by triggering use of the GRO path for
    packets with tunnel stacking, as demonstrated by
    interleaved IPv4 headers and GRE headers, a related
    issue to CVE-2016-7039 (bnc#1001486).

  - CVE-2016-9083: drivers/vfio/pci/vfio_pci.c in the Linux
    kernel allowed local users to bypass integer overflow
    checks, and cause a denial of service (memory
    corruption) or have unspecified other impact, by
    leveraging access to a vfio PCI device file for a
    VFIO_DEVICE_SET_IRQS ioctl call, aka a 'state machine
    confusion bug (bnc#1007197).

  - CVE-2016-9084: drivers/vfio/pci/vfio_pci_intrs.c in the
    Linux kernel misuses the kzalloc function, which allowed
    local users to cause a denial of service (integer
    overflow) or have unspecified other impact by leveraging
    access to a vfio PCI device file (bnc#1007197).

  - CVE-2016-9555: The sctp_sf_ootb function in
    net/sctp/sm_statefuns.c in the Linux kernel lacks
    chunk-length checking for the first chunk, which allowed
    remote attackers to cause a denial of service
    (out-of-bounds slab access) or possibly have unspecified
    other impact via crafted SCTP data (bnc#1011685).

  - CVE-2016-9794: A use-after-free in alsa pcm could lead
    to crashes or allowed local users to potentially gain
    privileges (bsc#1013533).

The following non-security bugs were fixed :

  - acpi / pad: do not register acpi_pad driver if running
    as Xen dom0 (bnc#995278).

  - Add power key support for PMIcs which are already
    included in the configs (boo#1012477). Arm64 already has
    these so no need to patch it.

  - alsa: hda - Bind with i915 only when Intel graphics is
    present (bsc#1012767).

  - alsa: hda - Clear the leftover component assignment at
    snd_hdac_i915_exit() (bsc#1012767).

  - alsa: hda - Degrade i915 binding failure message
    (bsc#1012767).

  - alsa: hda - Fix yet another i915 pointer leftover in
    error path (bsc#1012767).

  - alsa: hda - Gate the mic jack on HP Z1 Gen3 AiO
    (bsc#1004365).

  - arm64/efi: Enable runtime call flag checking
    (bsc#1005745).

  - arm64/efi: Move to generic {__,}efi_call_virt()
    (bsc#1005745).

  - arm64: Refuse to install 4k kernel on 64k system

  - arm64: Update config files. Disable
    CONFIG_IPMI_SI_PROBE_DEFAULTS (bsc#1006576)

  - arm: bcm2835: add CPU node for ARM core (boo#1012094).

  - arm: bcm2835: Split the DT for peripherals from the DT
    for the CPU (boo#1012094).

  - asoc: cht_bsw_rt5645: Enable jack detection
    (bsc#1010690).

  - asoc: cht_bsw_rt5645: Fix writing to string literal
    (bsc#1010690).

  - asoc: cht_bsw_rt5672: Use HID translation unit
    (bsc#1010690).

  - asoc: intel: add function stub when ACPI is not enabled
    (bsc#1010690).

  - asoc: Intel: add fw name to common dsp context
    (bsc#1010690).

  - asoc: Intel: Add missing 10EC5672 ACPI ID matching for
    Cherry Trail (bsc#1010690).

  - asoc: Intel: Add module tags for common match module
    (bsc#1010690).

  - asoc: Intel: add NULL test (bsc#1010690).

  - asoc: Intel: Add quirks for MinnowBoard MAX
    (bsc#1010690).

  - asoc: Intel: Add surface3 entry in CHT-RT5645 machine
    (bsc#1010690).

  - asoc: Intel: Atom: add 24-bit support for media playback
    and capture (bsc#1010690).

  - asoc: Intel: Atom: add deep buffer definitions for atom
    platforms (bsc#1010690).

  - asoc: Intel: Atom: add definitions for modem/SSP0
    interface (bsc#1010690).

  - asoc: Intel: Atom: Add quirk for Surface 3
    (bsc#1010690).

  - asoc: Intel: Atom: add support for CHT w/ RT5640
    (bsc#1010690).

  - asoc: Intel: Atom: Add support for HP ElitePad 1000 G2
    (bsc#1010690).

  - asoc: Intel: Atom: add support for RT5642 (bsc#1010690).

  - asoc: Intel: Atom: add terminate entry for dmi_system_id
    tables (bsc#1010690).

  - asoc: Intel: Atom: auto-detection of Baytrail-CR
    (bsc#1010690).

  - asoc: Intel: Atom: clean-up compressed DAI definition
    (bsc#1010690).

  - asoc: Intel: atom: enable configuration of SSP0
    (bsc#1010690).

  - asoc: Intel: atom: fix 0-day warnings (bsc#1010690).

  - asoc: Intel: Atom: fix boot warning (bsc#1010690).

  - asoc: Intel: Atom: Fix message handling during drop
    stream (bsc#1010690).

  - asoc: Intel: atom: fix missing breaks that would cause
    the wrong operation to execute (bsc#1010690).

  - asoc: Intel: Atom: fix regression on compress DAI
    (bsc#1010690).

  - asoc: Intel: Atom: flip logic for gain Switch
    (bsc#1010690).

  - asoc: Intel: atom: Make some messages to debug level
    (bsc#1010690).

  - asoc: Intel: Atom: move atom driver to common acpi match
    (bsc#1010690).

  - asoc: Intel: atom: statify cht_quirk (bsc#1010690).

  - asoc: Intel: boards: add DEEP_BUFFER support for
    BYT/CHT/BSW (bsc#1010690).

  - asoc: Intel: boards: align pin names between byt-rt5640
    drivers (bsc#1010690).

  - asoc: Intel: boards: merge DMI-based quirks in
    bytcr-rt5640 driver (bsc#1010690).

  - asoc: Intel: boards: start merging byt-rt5640 drivers
    (bsc#1010690).

  - asoc: Intel: bytcr_rt56040: additional routing quirks
    (bsc#1010690).

  - asoc: Intel: bytcr-rt5640: add Asus T100TAF quirks
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: add IN3 map (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: add MCLK support
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: Add quirk for Teclast X98 Air
    3G tablet (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: add SSP2_AIF2 routing
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: change quirk position
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: default routing and quirks on
    Baytrail-CR (bsc#1010690).

  - asoc: Intel: bytcr-rt5640: enable ASRC (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: enable differential mic quirk
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: fix dai/clock setup for SSP0
    routing (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: fixup DAI codec_name with HID
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: log quirks (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: quirk for Acer Aspire SWS-012
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: quirk for mono speaker
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: set SSP to I2S mode 2ch
    (bsc#1010690).

  - asoc: Intel: bytcr_rt5640: use HID translation util
    (bsc#1010690).

  - asoc: Intel: cht: fix uninit variable warning
    (bsc#1010690).

  - asoc: Intel: common: add translation from HID to
    codec-name (bsc#1010690).

  - asoc: Intel: common: filter ACPI devices with _STA
    return value (bsc#1010690).

  - asoc: Intel: common: increase the loglevel of 'FW Poll
    Status' (bsc#1010690).

  - asoc: Intel: Create independent acpi match module
    (bsc#1010690).

  - asoc: intel: Fix sst-dsp dependency on dw stuff
    (bsc#1010690).

  - asoc: Intel: Keep building old baytrail machine drivers
    (bsc#1010690).

  - asoc: Intel: Load the atom DPCM driver only
    (bsc#1010690).

  - asoc: intel: make function stub static (bsc#1010690).

  - asoc: Intel: Move apci find machine routines
    (bsc#1010690).

  - asoc: intel: Replace kthread with work (bsc#1010690).

  - asoc: Intel: Skylake: Always acquire runtime pm ref on
    unload (bsc#1005917).

  - asoc: Intel: sst: fix sst_memcpy32 wrong with non-4x
    bytes issue (bsc#1010690).

  - asoc: rt5640: add ASRC support (bsc#1010690).

  - asoc: rt5640: add internal clock source support
    (bsc#1010690).

  - asoc: rt5640: add master clock handling for rt5640
    (bsc#1010690).

  - asoc: rt5640: add supplys for dac power (bsc#1010690).

  - asoc: rt5640: remove unused variable (bsc#1010690).

  - asoc: rt5640: Set PLL src according to source
    (bsc#1010690).

  - asoc: rt5645: add DAC1 soft volume func control
    (bsc#1010690).

  - asoc: rt5645: Add dmi_system_id 'Google Setzer'
    (bsc#1010690).

  - asoc: rt5645: extend delay time for headphone pop noise
    (bsc#1010690).

  - asoc: rt5645: fix reg-2f default value (bsc#1010690).

  - asoc: rt5645: improve headphone pop when system resumes
    from S3 (bsc#1010690).

  - asoc: rt5645: improve IRQ reaction time for HS button
    (bsc#1010690).

  - asoc: rt5645: merge DMI tables of google projects
    (bsc#1010690).

  - asoc: rt5645: patch reg-0x8a (bsc#1010690).

  - asoc: rt5645: polling jd status in all conditions
    (bsc#1010690).

  - asoc: rt5645: Separate regmap for rt5645 and rt5650
    (bsc#1010690).

  - asoc: rt5645: set RT5645_PRIV_INDEX as volatile
    (bsc#1010690).

  - asoc: rt5645: use polling to support HS button
    (bsc#1010690).

  - asoc: rt5645: Use the mod_delayed_work instead of the
    queue_delayed_work and cancel_delayed_work_sync
    (bsc#1010690).

  - asoc: rt5670: Add missing 10EC5072 ACPI ID
    (bsc#1010690).

  - asoc: rt5670: Enable Braswell platform workaround for
    Dell Wyse 3040 (bsc#1010690).

  - asoc: rt5670: fix HP Playback Volume control
    (bsc#1010690).

  - asoc: rt5670: patch reg-0x8a (bsc#1010690).

  - blacklist.conf: Remove intel_pstate potential patch that
    SLE 12 SP2 The code layout upstream that motivated this
    patch is completely different to what is in SLE 12 SP2
    as schedutil was not backported.

  - bna: Add synchronization for tx ring (bsc#993739).

  - btrfs: allocate root item at snapshot ioctl time
    (bsc#1012452).

  - btrfs: better packing of btrfs_delayed_extent_op
    (bsc#1012452).

  - btrfs: Check metadata redundancy on balance
    (bsc#1012452).

  - btrfs: clean up an error code in btrfs_init_space_info()
    (bsc#1012452).

  - btrfs: cleanup, stop casting for extent_map->lookup
    everywhere (bsc#1012452).

  - btrfs: cleanup, use enum values for btrfs_path reada
    (bsc#1012452).

  - btrfs: deal with duplicates during extent_map insertion
    in btrfs_get_extent (bsc#1001171).

  - btrfs: deal with existing encompassing extent map in
    btrfs_get_extent() (bsc#1001171).

  - btrfs: do an allocation earlier during snapshot creation
    (bsc#1012452).

  - btrfs: do not create or leak aliased root while cleaning
    up orphans (bsc#994881).

  - btrfs: do not leave dangling dentry if symlink creation
    failed (bsc#1012452).

  - btrfs: do not use slab cache for struct
    btrfs_delalloc_work (bsc#1012452).

  - btrfs: drop duplicate prefix from scrub workqueues
    (bsc#1012452).

  - btrfs: drop unused parameter from lock_extent_bits
    (bsc#1012452).

  - btrfs: Enhance chunk validation check (bsc#1012452).

  - btrfs: Enhance super validation check (bsc#1012452).

  - btrfs: Ensure proper sector alignment for
    btrfs_free_reserved_data_space (bsc#1005666).

  - btrfs: Expoert and move leaf/subtree qgroup helpers to
    qgroup.c (bsc983087, bsc986255).

  - btrfs: fix incremental send failure caused by balance
    (bsc#985850).

  - btrfs: fix locking bugs when defragging leaves
    (bsc#1012452).

  - btrfs: fix memory leaks after transaction is aborted
    (bsc#1012452).

  - btrfs: fix output of compression message in
    btrfs_parse_options() (bsc#1012452).

  - btrfs: fix race between free space endio workers and
    space cache writeout (bsc#1012452).

  - btrfs: fix races on root_log_ctx lists (bsc#1007653).

  - btrfs: fix race when finishing dev replace leading to
    transaction abort (bsc#1012452).

  - btrfs: fix relocation incorrectly dropping data
    references (bsc#990384).

  - btrfs: fix typo in log message when starting a balance
    (bsc#1012452).

  - btrfs: fix unprotected list operations at
    btrfs_write_dirty_block_groups (bsc#1012452).

  - btrfs: handle quota reserve failure properly
    (bsc#1005666).

  - btrfs: make btrfs_close_one_device static (bsc#1012452).

  - btrfs: make clear_extent_bit helpers static inline
    (bsc#1012452).

  - btrfs: make clear_extent_buffer_uptodate return void
    (bsc#1012452).

  - btrfs: make end_extent_writepage return void
    (bsc#1012452).

  - btrfs: make extent_clear_unlock_delalloc return void
    (bsc#1012452).

  - btrfs: make extent_range_clear_dirty_for_io return void
    (bsc#1012452).

  - btrfs: make extent_range_redirty_for_io return void
    (bsc#1012452).

  - btrfs: make lock_extent static inline (bsc#1012452).

  - btrfs: make set_extent_bit helpers static inline
    (bsc#1012452).

  - btrfs: make set_extent_buffer_uptodate return void
    (bsc#1012452).

  - btrfs: make set_range_writeback return void
    (bsc#1012452).

  - btrfs: preallocate path for snapshot creation at ioctl
    time (bsc#1012452).

  - btrfs: put delayed item hook into inode (bsc#1012452).

  - btrfs: qgroup: Add comments explaining how btrfs qgroup
    works (bsc983087, bsc986255).

  - btrfs: qgroup: Fix qgroup data leaking by using subtree
    tracing (bsc983087, bsc986255).

  - btrfs: qgroup: Rename functions to make it follow
    reserve, trace, account steps (bsc983087, bsc986255).

  - btrfs: remove a trivial helper btrfs_set_buffer_uptodate
    (bsc#1012452).

  - btrfs: remove root_log_ctx from ctx list before
    btrfs_sync_log returns (bsc#1007653).

  - btrfs: remove unused inode argument from
    uncompress_inline() (bsc#1012452).

  - btrfs: remove wait from struct btrfs_delalloc_work
    (bsc#1012452).

  - btrfs: send, do not bug on inconsistent snapshots
    (bsc#985850).

  - btrfs: sink parameter wait to btrfs_alloc_delalloc_work
    (bsc#1012452).

  - btrfs: Support convert to -d dup for btrfs-convert
    (bsc#1012452).

  - btrfs: Update
    patches.suse/btrfs-8401-fix-qgroup-accounting-when-creat
    ing-snap.patch (bsc#972993).

  - btrfs: use GFP_KERNEL for allocations in ioctl handlers
    (bsc#1012452).

  - btrfs: use GFP_KERNEL for allocations of workqueues
    (bsc#1012452).

  - btrfs: use GFP_KERNEL for xattr and acl allocations
    (bsc#1012452).

  - btrfs: use smaller type for btrfs_path locks
    (bsc#1012452).

  - btrfs: use smaller type for btrfs_path lowest_level
    (bsc#1012452).

  - btrfs: use smaller type for btrfs_path reada
    (bsc#1012452).

  - btrfs: verbose error when we find an unexpected item in
    sys_array (bsc#1012452).

  - config: i2c: Enable CONFIG_I2C_DESIGNWARE_PLATFORM and
    *_BAYTRAIL (bsc#1010690) Realtek codecs on CHT platform
    require this i2c bus driver.

  - config: select new CONFIG_SND_SOC_INTEL_SST_* helpers

  - config: Update config files. (boo#1012094)

  - config: Update config files (bsc#1009454) Do not set
    CONFIG_EFI_SECURE_BOOT_SECURELEVEL in x86_64/default and
    x86_64/debug. We do not need to set
    CONFIG_EFI_SECURE_BOOT_SECURELEVEL in openSUSE kernel
    because openSUSE does not enable kernel module signature
    check (bsc#843661). Without kernel module signature
    check, the root account is allowed to load arbitrary
    kernel module to kernel space. Then lock functions by
    securelevel is pointless.

  - cxgbi: fix uninitialized flowi6 (bsc#963904
    FATE#320115).

  - Delete
    patches.fixes/Add-a-missed-complete-in-iscsit_close_conn
    ection.patch. remove patch
    Add-a-missed-complete-in-iscsit_close_connection.patch
    add bsc#997807 bsc#992555 in patch-4.4.27-28 references

  - dell-laptop: Fixate rfkill work on CPU#0 (bsc#1004052).

  - dell-wmi: Check if Dell WMI descriptor structure is
    valid (bsc#1004052).

  - dell-wmi: Clean up hotkey table size check
    (bsc#1004052).

  - dell-wmi: Ignore WMI event code 0xe045 (bsc#1004052).

  - dell-wmi: Improve unknown hotkey handling (bsc#1004052).

  - dell-wmi: Process only one event on devices with
    interface version 0 (bsc#1004052).

  - dell-wmi: Stop storing pointers to DMI tables
    (bsc#1004052).

  - dell-wmi: Support new hotkeys on the XPS 13 9350
    (Skylake) (bsc#1004052).

  - dell_wmi: Use a C99-style array for
    bios_to_linux_keycode (bsc#1004052).

  - drm/i915: Add missing ring_mask to Pineview
    (bsc#1005917).

  - drm/i915: Calculate watermark related members in the
    crtc_state, v4 (bsc#1011176).

  - drm/i915/ivb: Move WaCxSRDisabledForSpriteScaling w/a to
    atomic check (bsc#1011176).

  - drm/i915: Move disable_cxsr to the crtc_state
    (bsc#1011176).

  - drm/mgag200: fix error return code in mgag200fb_create()
    (bsc#1005917).

  - drm/radeon: Also call cursor_move_locked when the cursor
    size changes (bsc#1000433).

  - drm/radeon: Always store CRTC relative
    radeon_crtc->cursor_x/y values (bsc#1000433).

  - drm/radeon: Ensure vblank interrupt is enabled on DPMS
    transition to on (bsc#998054)

  - drm/radeon: Hide the HW cursor while it's out of bounds
    (bsc#1000433).

  - drm/radeon: Switch to drm_vblank_on/off (bsc#998054).

  - Drop kernel-obs-qa-xen unconditionally (bsc#1010040) The
    IBS cannot build it, even if there is a xen-capable
    kernel-obs-build.

  - edac/mce_amd: Add missing SMCA error descriptions
    (fate#320474, bsc#1013700).

  - edac/mce_amd: Use SMCA prefix for error descriptions
    arrays (fate#320474, bsc#1013700).

  - efi/runtime-wrappers: Add {__,}efi_call_virt() templates
    (bsc#1005745).

  - efi/runtime-wrappers: Detect firmware IRQ flag
    corruption (bsc#1005745).

  - efi/runtime-wrappers: Remove redundant #ifdefs
    (bsc#1005745).

  - ext4: fix data exposure after a crash (bsc#1012829).

  - fs, block: force direct-I/O for dax-enabled block
    devices (bsc#1012992).

  - fs/cifs: cifs_get_root shouldn't use path with tree name
    (bsc#963655, bsc#979681).

  - fs/cifs: Compare prepaths when comparing superblocks
    (bsc#799133).

  - fs/cifs: Fix memory leaks in cifs_do_mount()
    (bsc#799133).

  - fs/cifs: Move check for prefix path to within
    cifs_get_root() (bsc#799133).

  - fuse: Fixup buggy conflict resolution in
    patches.fixes/fuse-Propagate-dentry-down-to-inode_change
    _ok.patch.

  - genirq: Add untracked irq handler (bsc#1006827).

  - genirq: Use a common macro to go through the actions
    list (bsc#1006827).

  - gre: Disable segmentation offloads w/ CSUM and we are
    encapsulated via FOU (bsc#1001486).

  - gro: Allow tunnel stacking in the case of FOU/GUE
    (bsc#1001486).

  - hpsa: fallback to use legacy REPORT PHYS command
    (bsc#1006175).

  - hpsa: use bus '3' for legacy HBA devices (bsc#1010665).

  - hpsa: use correct DID_NO_CONNECT hostbyte (bsc#1010665).

  - hv: do not lose pending heartbeat vmbus packets
    (bnc#1006918).

  - i2c: designware-baytrail: Work around Cherry Trail
    semaphore errors (bsc#1011913).

  - i2c: xgene: Avoid dma_buffer overrun (bsc#1006576).

  - i40e: fix an uninitialized variable bug (bsc#969476
    FATE#319648).

  - i40e: fix broken i40e_config_rss_aq function (bsc#969476
    FATE#319648 bsc#969477 FATE#319816).

  - i40e: Remove redundant memset (bsc#969476 FATE#319648
    bsc#969477 FATE#319816).

  - i810: Enable Intel i810 audio driver used in OpenQA VMs.

  - Import kabi files for x86_64/default from 4.4.27-2.1

  - iommu/arm-smmu: Add support for 16 bit VMID
    (fate#319978).

  - iommu/arm-smmu: Workaround for ThunderX erratum #27704
    (fate#319978).

  - ipmi_si: create hardware-independent softdep for
    ipmi_devintf (bsc#1009062).

  - kABI: protect struct mmc_packed (kabi).

  - kABI: protect struct mmc_packed (kabi).

  - kABI: reintroduce sk_filter (kabi).

  - kABI: reintroduce strtobool (kabi).

  - kABI: reintroduce strtobool (kabi).

  - kABI: restore ip_cmsg_recv_offset parameters (kabi).

  - kabi/severities: Ignore kABI for asoc Intel SST drivers
    (bsc#1010690) These drivers are self-contained, not for
    3rd party drivers.

  - kernel-module-subpackage: Properly quote flavor in
    expressions That fixes a parse error if the flavor
    starts with a digit or contains other non-alphabetic
    characters.

  - kgr: ignore zombie tasks during the patching
    (bnc#1008979).

  - md/raid1: fix: IO can block resync indefinitely
    (bsc#1001310).

  - mm: do not use radix tree writeback tags for pages in
    swap cache (bnc#971975 VM performance -- swap).

  - mm/filemap: generic_file_read_iter(): check for zero
    reads unconditionally (bnc#1007955).

  - mm/mprotect.c: do not touch single threaded PTEs which
    are on the right node (bnc#971975 VM performance -- numa
    balancing).

  - net/mlx5: Add ConnectX-5 PCIe 4.0 to list of supported
    devices (bsc#1006809).

  - net: sctp, forbid negative length (bnc#1005921).

  - netvsc: fix incorrect receive checksum offloading
    (bnc#1006915).

  - overlayfs: allow writing on read-only btrfs subvolumes
    (bsc#1010158)

  - pci/ACPI: Allow all PCIe services on non-ACPI host
    bridges (bsc#1006827).

  - pci: Allow additional bus numbers for hotplug bridges
    (bsc#1006827).

  - pci: correctly cast mem_base in
    pci_read_bridge_mmio_pref() (bsc#1001888).

  - pci: pciehp: Allow exclusive userspace control of
    indicators (bsc#1006827).

  - pci: Remove return values from
    pcie_port_platform_notify() and relatives (bsc#1006827).

  - perf/x86: Add perf support for AMD family-17h processors
    (fate#320473).

  - powerpc/pseries: Use H_CLEAR_HPT to clear MMU hash table
    during kexec (bsc#1003813).

  - proc: much faster /proc/vmstat (bnc#971975 VM
    performance -- vmstat).

  - qede: Correctly map aggregation replacement pages
    (bsc#966318 FATE#320158 bsc#966316 FATE#320159).

  - qed: FLR of active VFs might lead to FW assert
    (bsc#966318 FATE#320158 bsc#966316 FATE#320159).

  - Reformat spec files according to the format_spec_file
    osc helper

  - Replace
    patches.kabi/kabi-hide-new-member-recursion_counter-in-s
    truct-sk_.patch by
    patches.kabi/kabi-hide-bsc-1001486-changes-in-struct-nap
    i_gro_cb.patch

  - Revert 'ACPI / LPSS: allow to use specific PM domain
    during ->probe()' (bsc#1005917).

  - Revert 'fix minor infoleak in get_user_ex()' (p.k.o).

  - REVERT fs/cifs: fix wrongly prefixed path to root
    (bsc#963655, bsc#979681)

  - Revert 'x86/mm: Expand the exception table logic to
    allow new handling options' (p.k.o).

  - rpm/config.sh: Build against SP2 in the OBS as well

  - rpm/constraints.in: increase disk for kernel-syzkaller
    The kernel-syzkaller build now consumes around 30G. This
    causes headache in factory where the package rebuilds
    over and over. Require 35G disk size to successfully
    build the flavor.

  - rpm/kernel-binary.spec.in: Build the -base package
    unconditionally (bsc#1000118)

  - rpm/kernel-binary.spec.in: Do not create KMPs with
    CONFIG_MODULES=n

  - rpm/kernel-binary.spec.in: Only build -base and -extra
    with CONFIG_MODULES (bsc#1000118)

  - rpm/kernel-binary.spec.in: Simplify debug info switch
    Any CONFIG_DEBUG_INFO sub-options are answered in the
    configs nowadays.

  - rpm/kernel-spec-macros: Ignore too high rebuild counter
    (bsc#1012060)

  - rpm/mkspec: Read a default release string from
    rpm/config.sh (bsc997059)

  - rpm/package-descriptions: Add 64kb kernel flavor
    description

  - rpm/package-descriptions: add kernel-syzkaller

  - rpm/package-descriptions: pv has been merged into
    -default (fate#315712)

  - rpm/package-descriptions: the flavor is 64kb, not 64k

  - sched/core: Optimize __schedule() (bnc#978907 Scheduler
    performance -- context switch).

  - sched/fair: Optimize find_idlest_cpu() when there is no
    choice (bnc#978907 Scheduler performance -- idle
    search).

  - supported.conf: Add overlay.ko to -base (fate#321903)
    Also, delete the stale entry for the old overlayfs.

  - supported.conf: Mark vmx-crypto as supported
    (fate#319564)

  - tg3: Avoid NULL pointer dereference in
    tg3_io_error_detected() (bsc#963609 FATE#320143).

  - usbhid: add ATEN CS962 to list of quirky devices
    (bsc#1007615).

  - Whitelist KVM KABI changes resulting from adding a
    hcall. caused by
    5246adec59458b5d325b8e1462ea9ef3ead7f6ae
    powerpc/pseries: Use H_CLEAR_HPT to clear MMU hash table
    during kexec No problem is expected as result of
    changing KVM KABI so whitelisting for now. If we get
    some additional input from IBM we can back out the
    patch.

  - writeback: initialize inode members that track writeback
    history (bsc#1012829).

  - x86/apic: Order irq_enter/exit() calls correctly vs.
    ack_APIC_irq() (bsc#1013479).

  - x86/efi: Enable runtime call flag checking
    (bsc#1005745).

  - x86/efi: Move to generic {__,}efi_call_virt()
    (bsc#1005745).

  - x86/mce/AMD, EDAC/mce_amd: Define and use tables for
    known SMCA IP types (fate#320474, bsc#1013700). Exclude
    removed symbols from kABI check. They're AMD Zen
    relevant only and completely useless to other modules -
    only edac_mce_amd.ko.

  - x86/mce/AMD: Increase size of the bank_map type
    (fate#320474, bsc#1013700).

  - x86/mce/AMD: Read MSRs on the CPU allocating the
    threshold blocks (fate#320474, bsc#1013700).

  - x86/mce/AMD: Update sysfs bank names for SMCA systems
    (fate#320474, bsc#1013700).

  - x86/mce/AMD: Use msr_ops.misc() in
    allocate_threshold_blocks() (fate#320474, bsc#1013700).

  - x86/PCI: VMD: Attach VMD resources to parent domain's
    resource tree (bsc#1006827).

  - x86/PCI: VMD: Document code for maintainability
    (bsc#1006827).

  - x86/PCI: VMD: Fix infinite loop executing irq's
    (bsc#1006827).

  - x86/PCI: VMD: Initialize list item in IRQ disable
    (bsc#1006827).

  - x86/PCI: VMD: Request userspace control of PCIe hotplug
    indicators (bsc#1006827).

  - x86/PCI: VMD: Select device dma ops to override
    (bsc#1006827).

  - x86/PCI: VMD: Separate MSI and MSI-X vector sharing
    (bsc#1006827).

  - x86/PCI: VMD: Set bus resource start to 0 (bsc#1006827).

  - x86/PCI: VMD: Use lock save/restore in interrupt enable
    path (bsc#1006827).

  - x86/PCI/VMD: Use untracked irq handler (bsc#1006827).

  - x86/PCI: VMD: Use x86_vector_domain as parent domain
    (bsc#1006827).

  - xen/gntdev: Use VM_MIXEDMAP instead of VM_IO to avoid
    NUMA balancing (bnc#1005169).

  - zram: Fix unbalanced idr management at hot removal
    (bsc#1010970)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1000433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1001888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1003813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1005929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1006918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1007955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1009454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1013700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=799133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=843661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=914939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=954986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=992555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=994881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=997807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=998054"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-docs-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-build-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-obs-qa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-base-debuginfo-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debuginfo-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-debugsource-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-debug-devel-debuginfo-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-base-debuginfo-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debuginfo-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-debugsource-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-default-devel-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-devel-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-html-4.4.36-5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-docs-pdf-4.4.36-5.3") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-macros-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-build-debugsource-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-obs-qa-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-source-vanilla-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-syms-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-base-debuginfo-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debuginfo-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-debugsource-4.4.36-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"kernel-vanilla-devel-4.4.36-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-docs-html / kernel-docs-pdf / kernel-devel / kernel-macros / etc");
}
