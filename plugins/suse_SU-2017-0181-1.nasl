#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:0181-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(96603);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/01/18 14:49:21 $");

  script_cve_id("CVE-2015-1350", "CVE-2015-8964", "CVE-2016-7039", "CVE-2016-7042", "CVE-2016-7425", "CVE-2016-7913", "CVE-2016-7917", "CVE-2016-8645", "CVE-2016-8666", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9793", "CVE-2016-9919");
  script_osvdb_id(117818, 144411, 145388, 145585, 145649, 145694, 146370, 146377, 147000, 147016, 147057, 147168, 148409, 148442);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2017:0181-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 SP2 kernel was updated to 4.4.38 to
receive various security and bugfixes. The following security bugs
were fixed :

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

  - CVE-2016-7039: The IP stack in the Linux kernel allowed
    remote attackers to cause a denial of service (stack
    consumption and panic) or possibly have unspecified
    other impact by triggering use of the GRO path for large
    crafted packets, as demonstrated by packets that contain
    only VLAN headers, a related issue to CVE-2016-8666
    (bnc#1001486).

  - CVE-2016-7042: The proc_keys_show function in
    security/keys/proc.c in the Linux kernel through 4.8.2,
    when the GNU Compiler Collection (gcc) stack protector
    is enabled, uses an incorrect buffer size for certain
    timeout data, which allowed local users to cause a
    denial of service (stack memory corruption and panic) by
    reading the /proc/keys file (bnc#1004517).

  - CVE-2016-7425: The arcmsr_iop_message_xfer function in
    drivers/scsi/arcmsr/arcmsr_hba.c in the Linux kernel did
    not restrict a certain length field, which allowed local
    users to gain privileges or cause a denial of service
    (heap-based buffer overflow) via an
    ARCMSR_MESSAGE_WRITE_WQBUFFER control code (bnc#999932).

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

  - CVE-2016-8645: The TCP stack in the Linux kernel
    mishandled skb truncation, which allowed local users to
    cause a denial of service (system crash) via a crafted
    application that made sendto system calls, related to
    net/ipv4/tcp_ipv4.c and net/ipv6/tcp_ipv6.c
    (bnc#1009969).

  - CVE-2016-8666: The IP stack in the Linux kernel allowed
    remote attackers to cause a denial of service (stack
    consumption and panic) or possibly have unspecified
    other impact by triggering use of the GRO path for
    packets with tunnel stacking, as demonstrated by
    interleaved IPv4 headers and GRE headers, a related
    issue to CVE-2016-7039 (bnc#1003964).

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

  - CVE-2016-9793: A bug in SO_{SND|RCV}BUFFORCE
    setsockopt() implementation was fixed, which allowed
    CAP_NET_ADMIN users to cause memory corruption.
    (bsc#1013531).

  - CVE-2016-9919: The icmp6_send function in
    net/ipv6/icmp.c in the Linux kernel omits a certain
    check of the dst data structure, which allowed remote
    attackers to cause a denial of service (panic) via a
    fragmented IPv6 packet (bnc#1014701). The following
    non-security bugs were fixed :

  - 8250_pci: Fix potential use-after-free in error path
    (bsc#1013001).

  - acpi / PAD: do not register acpi_pad driver if running
    as Xen dom0 (bnc#995278).

  - Add mainline tags to various hyperv patches

  - alsa: fm801: detect FM-only card earlier (bsc#1005917).

  - alsa: fm801: explicitly free IRQ line (bsc#1005917).

  - alsa: fm801: propagate TUNER_ONLY bit when autodetected
    (bsc#1005917).

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

  - alsa: hda - Turn off loopback mixing as default
    (bsc#1001462).

  - apparmor: add missing id bounds check on dfa
    verification (bsc#1000304).

  - apparmor: check that xindex is in trans_table bounds
    (bsc#1000304).

  - apparmor: do not check for vmalloc_addr if kvzalloc()
    failed (bsc#1000304).

  - apparmor: do not expose kernel stack (bsc#1000304).

  - apparmor: ensure the target profile name is always
    audited (bsc#1000304).

  - apparmor: exec should not be returning ENOENT when it
    denies (bsc#1000304).

  - apparmor: fix audit full profile hname on successful
    load (bsc#1000304).

  - apparmor: fix change_hat not finding hat after policy
    replacement (bsc#1000287).

  - apparmor: fix disconnected bind mnts reconnection
    (bsc#1000304).

  - apparmor: fix log failures for all profiles in a set
    (bsc#1000304).

  - apparmor: fix module parameters can be changed after
    policy is locked (bsc#1000304).

  - apparmor: fix oops in profile_unpack() when policy_db is
    not present (bsc#1000304).

  - apparmor: fix put() parent ref after updating the active
    ref (bsc#1000304).

  - apparmor: fix refcount bug in profile replacement
    (bsc#1000304).

  - apparmor: fix refcount race when finding a child profile
    (bsc#1000304).

  - apparmor: fix replacement bug that adds new child to old
    parent (bsc#1000304).

  - apparmor: fix uninitialized lsm_audit member
    (bsc#1000304).

  - apparmor: fix update the mtime of the profile file on
    replacement (bsc#1000304).

  - apparmor: internal paths should be treated as
    disconnected (bsc#1000304).

  - apparmor: use list_next_entry instead of list_entry_next
    (bsc#1000304).

  - arm64: Call numa_store_cpu_info() earlier.

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

  - asoc: fsl_ssi: mark SACNT register volatile
    (bsc#1005917).

  - asoc: imx-spdif: Fix crash on suspend (bsc#1005917).

  - asoc: intel: add function stub when ACPI is not enabled
    (bsc#1010690).

  - asoc: Intel: add fw name to common dsp context
    (bsc#1010690).

  - asoc: Intel: Add missing 10EC5672 ACPI ID matching for
    Cherry Trail (bsc#1010690).

  - asoc: Intel: Add module tags for common match module
    (bsc#1010690).

  - asoc: Intel: add NULL test (bsc#1010690).

  - AsoC: Intel: Add quirks for MinnowBoard MAX
    (bsc#1010690).

  - asoc: Intel: Add surface3 entry in CHT-RT5645 machine
    (bsc#1010690).

  - asoc: Intel: Atom: add 24-bit support for media playback
    and capture (bsc#1010690).

  - ASoc: Intel: Atom: add deep buffer definitions for atom
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

  - asoc: Intel: bytcr_rt5640: fallback mechanism if MCLK is
    not enabled (bsc#1010690).

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

  - asoc: Intel: pass correct parameter in
    sst_alloc_stream_mrfld() (bsc#1005917).

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

  - asoc: simple-card: do not fail if sysclk setting is not
    supported (bsc#1005917).

  - asoc: tegra_alc5632: check return value (bsc#1005917).

  - asoc: wm8960: Fix WM8960_SYSCLK_PLL mode (bsc#1005917).

  - autofs: fix multiple races (bsc#997639).

  - autofs: use dentry flags to block walks during expire
    (bsc#997639).

  - blacklist.conf: Add dup / unapplicable commits
    (bsc#1005545).

  - blacklist.conf: Add i915 stable commits that can be
    ignored (bsc#1015367)

  - blacklist.conf: add inapplicable / duped commits
    (bsc#1005917)

  - blacklist.conf: ignore commit bfe6c8a89e03 ('arm64: Fix
    NUMA build error when !CONFIG_ACPI')

  - blacklist.conf: Remove intel_pstate potential patch that
    SLE 12 SP2 The code layout upstream that motivated this
    patch is completely different to what is in SLE 12 SP2
    as schedutil was not backported.

  - block_dev: do not test bdev->bd_contains when it is not
    stable (bsc#1008557).

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

  - btrfs: fix endless loop in balancing block groups
    (bsc#1006804).

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

  - cdc-acm: added sanity checking for probe() (bsc#993891).

  - cxgbi: fix uninitialized flowi6 (bsc#963904
    FATE#320115).

  - Delete
    patches.fixes/apparmor-initialize-common_audit_data.patc
    h (bsc#1000304) It'll be fixed in the upcoming apparmor
    fix series from upstream.

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

  - Drivers: hv: utils: fix a race on userspace daemons
    registration (bnc#1014392).

  - drm/amdgpu: Do not leak runtime pm ref on driver load
    (bsc#1005545).

  - drm/amdgpu: Do not leak runtime pm ref on driver unload
    (bsc#1005545).

  - drm/i915: Acquire audio powerwell for HD-Audio registers
    (bsc#1005545).

  - drm/i915: add helpers for platform specific revision id
    range checks (bsc#1015367).

  - drm/i915: Add missing ring_mask to Pineview
    (bsc#1005917).

  - drm/i915: Apply broader WaRsDisableCoarsePowerGating for
    guc also (bsc#1015367).

  - drm/i915/bxt: add revision id for A1 stepping and use it
    (bsc#1015367).

  - drm/i915: Calculate watermark related members in the
    crtc_state, v4 (bsc#1011176).

  - drm/i915: Call intel_dp_mst_resume() before resuming
    displays (bsc#1015359).

  - drm/i915: call kunmap_px on pt_vaddr (bsc#1005545).

  - drm/i915: Cleaning up DDI translation tables
    (bsc#1014392).

  - drm/i915: Clean up L3 SQC register field definitions
    (bsc#1014392).

  - drm/i915/dsi: fix CHV dsi encoder hardware state readout
    on port C (bsc#1015367).

  - drm/i915: Enable polling when we do not have hpd
    (bsc#1014120).

  - drm/i915: Exit cherryview_irq_handler() after one pass
    (bsc#1015367).

  - drm/i915: Fix iboost setting for SKL Y/U DP DDI buffer
    translation entry 2 (bsc#1014392).

  - drm/i915: Fix system resume if PCI device remained
    enabled (bsc#1015367).

  - drm/i915: fix the SDE irq dmesg warnings properly
    (bsc#1005545).

  - drm/i915: Fix VBT backlight Hz to PWM conversion for PNV
    (bsc#1005545).

  - drm/i915: Fix vbt PWM max setup for CTG (bsc#1005545).

  - drm/i915: Force ringbuffers to not be at offset 0
    (bsc#1015367).

  - drm/i915/gen9: Add WaInPlaceDecompressionHang
    (bsc#1014392).

  - drm/i915/ivb: Move WaCxSRDisabledForSpriteScaling w/a to
    atomic check (bsc#1011176).

  - drm/i915: Kill intel_runtime_pm_disable() (bsc#1005545).

  - drm/i915: Make plane fb tracking work correctly, v2
    (bsc#1004048).

  - drm/i915: Make prepare_plane_fb fully interruptible
    (bsc#1004048).

  - drm/i915: Move disable_cxsr to the crtc_state
    (bsc#1011176).

  - drm/i915: On fb alloc failure, unref gem object where it
    gets refed (bsc#1005545).

  - drm/i915: Only call commit_planes when there are things
    to commit (bsc#1004048).

  - drm/i915: Only commit active planes when updating planes
    during reset (bsc#1004048).

  - drm/i915: Only run commit when crtc is active, v2
    (bsc#1004048).

  - drm/i915: remove parens around revision ids
    (bsc#1015367).

  - drm/i915: Set crtc_state->lane_count for HDMI
    (bsc#1005545).

  - drm/i915/skl: Add WaDisableGafsUnitClkGating
    (bsc#1014392).

  - drm/i915/skl: Fix rc6 based gpu/system hang
    (bsc#1015367).

  - drm/i915/skl: Fix spurious gpu hang with gt3/gt4 revs
    (bsc#1015367).

  - drm/i915/skl: Update DDI translation tables for SKL
    (bsc#1014392).

  - drm/i915/skl: Update watermarks before the crtc is
    disabled (bsc#1015367).

  - drm/i915: suppress spurious !wm_changed warning
    (bsc#1006267).

  - drm/i915: Unconditionally flush any chipset buffers
    before execbuf (bsc#1005545).

  - drm/i915: Update legacy primary state outside the commit
    hook, v2 (bsc#1004048).

  - drm/i915: Update Skylake DDI translation table for DP
    (bsc#1014392).

  - drm/i915: Update Skylake DDI translation table for HDMI
    (bsc#1014392).

  - drm/i915/userptr: Hold mmref whilst calling
    get-user-pages (bsc#1015367).

  - drm/i915/vlv: Disable HPD in
    valleyview_crt_detect_hotplug() (bsc#1014120).

  - drm/i915/vlv: Make intel_crt_reset() per-encoder
    (bsc#1014120).

  - drm/i915/vlv: Reset the ADPA in
    vlv_display_power_well_init() (bsc#1014120).

  - drm/i915: Wait for power cycle delay after turning off
    DSI panel power (bsc#1005545).

  - drm/i915: Wait up to 3ms for the pcu to ack the cdclk
    change request on SKL (bsc#1005545).

  - drm/layerscape: reduce excessive stack usage
    (bsc#1005545).

  - drm/mgag200: fix error return code in mgag200fb_create()
    (bsc#1005917).

  - drm/nouveau: Do not leak runtime pm ref on driver unload
    (bsc#1005545).

  - drm/radeon: Also call cursor_move_locked when the cursor
    size changes (bsc#1000433).

  - drm/radeon: Always store CRTC relative
    radeon_crtc->cursor_x/y values (bsc#1000433).

  - drm/radeon/ci add comment to document intentionally
    unreachable code (bsc#1005545).

  - drm/radeon: Do not leak runtime pm ref on driver load
    (bsc#1005545).

  - drm/radeon: Do not leak runtime pm ref on driver unload
    (bsc#1005545).

  - drm/radeon: Ensure vblank interrupt is enabled on DPMS
    transition to on (bsc#998054)

  - drm/radeon: Hide the HW cursor while it's out of bounds
    (bsc#1000433).

  - drm/radeon: Switch to drm_vblank_on/off (bsc#998054).

  - drm/rockchip: fix a couple off by one bugs
    (bsc#1005545).

  - drm/tegra: checking for IS_ERR() instead of NULL
    (bsc#1005545).

  - edac/mce_amd: Add missing SMCA error descriptions
    (fate#320474, bsc#1013700).

  - edac/mce_amd: Use SMCA prefix for error descriptions
    arrays (fate#320474, bsc#1013700).

  - efi/arm64: Do not apply MEMBLOCK_NOMAP to UEFI memory
    map mapping (bsc#986987).

  - efi: ARM: avoid warning about phys_addr_t cast.

  - efi/runtime-wrappers: Add {__,}efi_call_virt() templates
    (bsc#1005745).

  - efi/runtime-wrappers: Detect firmware IRQ flag
    corruption (bsc#1005745).

  - efi/runtime-wrappers: Remove redundant #ifdefs
    (bsc#1005745).

  - ext4: fix data exposure after a crash (bsc#1012829).

  - Fix kabi change cause by adding flock_owner to
    open_context (bsc#998689).

  - Fixup UNMAP calculation (bsc#1005327)

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

  - fs/select: add vmalloc fallback for select(2)
    (bsc#1000189).

  - genirq: Add untracked irq handler (bsc#1006827).

  - genirq: Use a common macro to go through the actions
    list (bsc#1006827).

  - gpio: generic: make bgpio_pdata always visible.

  - gpio: Restore indentation of parent device setup.

  - gre: Disable segmentation offloads w/ CSUM and we are
    encapsulated via FOU (bsc#1001486).

  - gro: Allow tunnel stacking in the case of FOU/GUE
    (bsc#1001486).

  - gro_cells: mark napi struct as not busy poll candidates
    (bsc#966191 FATE#320230 bsc#966186 FATE#320228).

  - group-source-files.pl: mark arch/*/scripts as devel
    make[2]:
    /usr/src/linux-4.6.4-2/arch/powerpc/scripts/gcc-check-mp
    rofile-kernel.sh: C ommand not found

  - hpsa: fallback to use legacy REPORT PHYS command
    (bsc#1006175).

  - hpsa: use bus '3' for legacy HBA devices (bsc#1010665).

  - hpsa: use correct DID_NO_CONNECT hostbyte (bsc#1010665).

  - hv: do not lose pending heartbeat vmbus packets
    (bnc#1006918).

  - i2c: designware-baytrail: Add support for cherrytrail
    (bsc#1011913).

  - i2c: designware-baytrail: Pass dw_i2c_dev into helper
    functions (bsc#1011913).

  - i2c: designware-baytrail: Work around Cherry Trail
    semaphore errors (bsc#1011913).

  - i2c: designware: Prevent runtime suspend during adapter
    registration (bsc#1011913).

  - i2c: designware: retry transfer on transient failure
    (bsc#1011913).

  - i2c: designware: Use transfer timeout from ioctl
    I2C_TIMEOUT (bsc#1011913).

  - i2c: Enable CONFIG_I2C_DESIGNWARE_PLATFORM and
    *_BAYTRAIL (bsc#1010690) Realtek codecs on CHT platform
    require this i2c bus driver.

  - i2c: xgene: Avoid dma_buffer overrun (bsc#1006576).

  - i40e: fix an uninitialized variable bug (bsc#969476
    FATE#319648).

  - i40e: fix broken i40e_config_rss_aq function (bsc#969476
    FATE#319648 bsc#969477 FATE#319816).

  - i40e: Remove redundant memset (bsc#969476 FATE#319648
    bsc#969477 FATE#319816).

  - i40iw: Add missing check for interface already open
    (bsc#974842 FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Add missing NULL check for MPA private data
    (bsc#974842 FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Avoid writing to freed memory (bsc#974842
    FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Change mem_resources pointer to a u8 (bsc#974842
    FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Do not set self-referencing pointer to NULL after
    kfree (bsc#974842 FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Fix double free of allocated_buffer (bsc#974842
    FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Protect req_resource_num update (bsc#974842
    FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Receive notification events correctly (bsc#974842
    FATE#319831 bsc#974843 FATE#319832).

  - i40iw: Send last streaming mode message for loopback
    connections (bsc#974842 FATE#319831 bsc#974843
    FATE#319832).

  - i40iw: Update hw_iwarp_state (bsc#974842 FATE#319831
    bsc#974843 FATE#319832).

  - ib/core: Fix possible memory leak in
    cma_resolve_iboe_route() (bsc#966191 FATE#320230
    bsc#966186 FATE#320228).

  - ib/mlx5: Fix iteration overrun in GSI qps (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - ib/mlx5: Fix steering resource leak (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - ib/mlx5: Set source mac address in FTE (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - ibmvnic: convert to use simple_open() (bsc#1015416).

  - ibmvnic: Driver Version 1.0.1 (bsc#1015416).

  - ibmvnic: drop duplicate header seq_file.h (bsc#1015416).

  - ibmvnic: fix error return code in ibmvnic_probe()
    (bsc#1015416).

  - ibmvnic: Fix GFP_KERNEL allocation in interrupt context
    (bsc#1015416).

  - ibmvnic: Fix missing brackets in init_sub_crq_irqs
    (bsc#1015416).

  - ibmvnic: Fix releasing of sub-CRQ IRQs in interrupt
    context (bsc#1015416).

  - ibmvnic: Fix size of debugfs name buffer (bsc#1015416).

  - ibmvnic: Handle backing device failover and
    reinitialization (bsc#1015416).

  - ibmvnic: Start completion queue negotiation at
    server-provided optimum values (bsc#1015416).

  - ibmvnic: Unmap ibmvnic_statistics structure
    (bsc#1015416).

  - ibmvnic: Update MTU after device initialization
    (bsc#1015416).

  - input: ALPS - add touchstick support for SS5 hardware
    (bsc#987703).

  - input: ALPS - allow touchsticks to report pressure
    (bsc#987703).

  - input: ALPS - handle 0-pressure 1F events (bsc#987703).

  - input: ALPS - set DualPoint flag for 74 03 28 devices
    (bsc#987703).

  - iommu/arm-smmu: Add support for 16 bit VMID
    (fate#319978).

  - iommu/arm-smmu: Workaround for ThunderX erratum #27704
    (fate#319978).

  - ipc/sem.c: add cond_resched in exit_sme (bsc#979378).

  - ipmi_si: create hardware-independent softdep for
    ipmi_devintf (bsc#1009062).

  - ixgbe: Do not clear RAR entry when clearing VMDq for SAN
    MAC (bsc#969474 FATE#319812 bsc#969475 FATE#319814).

  - ixgbe: Force VLNCTRL.VFE to be set in all VMDq paths
    (bsc#969474 FATE#319812 bsc#969475 FATE#319814).

  - kABI: protect struct dw_mci.

  - kABI: protect struct mmc_packed (kabi).

  - kABI: reintroduce iov_iter_fault_in_multipages_readable.

  - kABI: reintroduce sk_filter (kabi).

  - kABI: reintroduce strtobool (kabi).

  - kABI: restore ip_cmsg_recv_offset parameters (kabi).

  - kabi/severities: Ignore kABI for asoc Intel SST drivers
    (bsc#1010690) These drivers are self-contained, not for
    3rd party drivers.

  - kabi/severities: Whitelist libceph and rbd (bsc#988715).
    Like SLE12-SP1.

  - kernel-module-subpackage: Properly quote flavor in
    expressions That fixes a parse error if the flavor
    starts with a digit or contains other non-alphabetic
    characters.

  - kgr: ignore zombie tasks during the patching
    (bnc#1008979).

  - kvm: arm/arm64: Fix occasional warning from the timer
    work function (bsc#988524).

  - kvm: x86: correctly reset dest_map->vector when
    restoring LAPIC state (bsc#966471).

  - libceph: enable large, variable-sized OSD requests
    (bsc#988715).

  - libceph: make r_request msg_size calculation clearer
    (bsc#988715).

  - libceph: move r_reply_op_{len,result} into struct
    ceph_osd_req_op (bsc#988715).

  - libceph: osdc->req_mempool should be backed by a slab
    pool (bsc#988715).

  - libceph: rename ceph_osd_req_op::payload_len to
    indata_len (bsc#988715).

  - lib/mpi: avoid assembler warning (bsc#1003581).

  - lib/mpi: mpi_read_buffer(): fix buffer overflow
    (bsc#1003581).

  - lib/mpi: mpi_read_buffer(): optimize skipping of leading
    zero limbs (bsc#1003581).

  - lib/mpi: mpi_read_buffer(): replace open coded endian
    conversion (bsc#1003581).

  - lib/mpi: mpi_write_sgl(): fix out-of-bounds stack access
    (bsc#1003581).

  - lib/mpi: mpi_write_sgl(): fix style issue with lzero
    decrement (bsc#1003581).

  - lib/mpi: mpi_write_sgl(): purge redundant pointer
    arithmetic (bsc#1003581).

  - lib/mpi: mpi_write_sgl(): replace open coded endian
    conversion (bsc#1003581).

  - lib/mpi: use 'static inline' instead of 'extern inline'
    (bsc#1003581).

  - locking/pv-qspinlock: Use cmpxchg_release() in
    __pv_queued_spin_unlock() (bsc#969756).

  - locking/rtmutex: Prevent dequeue vs. unlock race
    (bsc#1015212).

  - locking/rtmutex: Use READ_ONCE() in rt_mutex_owner()
    (bsc#1015212).

  - mailbox/xgene-slimpro: Checking for IS_ERR instead of
    NULL.

  - md/raid1: fix: IO can block resync indefinitely
    (bsc#1001310).

  - mlx4: Do not BUG_ON() if device reset failed
    (bsc#1001888).

  - mm: do not use radix tree writeback tags for pages in
    swap cache (bnc#971975 VM performance -- swap).

  - mm: filemap: do not plant shadow entries without radix
    tree node (bnc#1005929).

  - mm: filemap: fix mapping->nrpages double accounting in
    fuse (bnc#1005929).

  - mm/filemap: generic_file_read_iter(): check for zero
    reads unconditionally (bnc#1007955).

  - mm/mprotect.c: do not touch single threaded PTEs which
    are on the right node (bnc#971975 VM performance -- numa
    balancing).

  - mm: workingset: fix crash in shadow node shrinker caused
    by replace_page_cache_page() (bnc#1005929).

  - mm/zswap: use workqueue to destroy pool (VM
    Functionality, bsc#1005923).

  - net: icmp6_send should use dst dev to determine L3
    domain (bsc#1014701).

  - net: ipv6: tcp reset, icmp need to consider L3 domain
    (bsc#1014701).

  - net/mlx4_en: Fix panic on xmit while port is down
    (bsc#966191 FATE#320230).

  - net/mlx5: Add ConnectX-5 PCIe 4.0 to list of supported
    devices (bsc#1006809).

  - net/mlx5: Add error prints when validate ETS failed
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5: Avoid setting unused var when modifying vport
    node GUID (bsc#966170 FATE#320225 bsc#966172
    FATE#320226).

  - net/mlx5e: Use correct flow dissector key on flower
    offloading (bsc#966170 FATE#320225 bsc#966172
    FATE#320226).

  - net/mlx5: Fix autogroups groups num not decreasing
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net/mlx5: Fix teardown errors that happen in pci error
    handler (bsc#1001169).

  - net/mlx5: Keep autogroups list ordered (bsc#966170
    FATE#320225 bsc#966172 FATE#320226).

  - net_sched: fix a typo in tc_for_each_action()
    (bsc#966170 FATE#320225 bsc#966172 FATE#320226).

  - net: sctp, forbid negative length (bnc#1005921).

  - netvsc: fix incorrect receive checksum offloading
    (bnc#1006915).

  - nfs: nfs4_fl_prepare_ds must be careful about reporting
    success (bsc#1000776).

  - nfsv4: add flock_owner to open context (bnc#998689).

  - nfsv4: change nfs4_do_setattr to take an open_context
    instead of a nfs4_state (bnc#998689).

  - nfsv4: change nfs4_select_rw_stateid to take a
    lock_context inplace of lock_owner (bnc#998689).

  - nfsv4: enhance nfs4_copy_lock_stateid to use a flock
    stateid if there is one (bnc#998689).

  - oom: print nodemask in the oom report (bnc#1003866).

  - overlayfs: allow writing on read-only btrfs subvolumes
    (bsc#1010158)

  - pci/acpi: Allow all PCIe services on non-ACPI host
    bridges (bsc#1006827).

  - pci: Allow additional bus numbers for hotplug bridges
    (bsc#1006827).

  - pci: correctly cast mem_base in
    pci_read_bridge_mmio_pref() (bsc#1001888).

  - pci: Do not set RCB bit in LNKCTL if the upstream bridge
    hasn't (bsc#1001888).

  - pci: Fix BUG on device attach failure (bnc#987641).

  - pci: pciehp: Allow exclusive userspace control of
    indicators (bsc#1006827).

  - pci: Remove return values from
    pcie_port_platform_notify() and relatives (bsc#1006827).

  - perf/x86: Add perf support for AMD family-17h processors
    (fate#320473).

  - pm / hibernate: Fix 2G size issue of snapshot image
    verification (bsc#1004252).

  - pm / sleep: declare __tracedata symbols as char rather
    than char (bnc#1005895).

  - powercap/intel_rapl: Add support for Kabylake
    (bsc#1003566).

  - powercap / RAPL: add support for Denverton
    (bsc#1003566).

  - powercap / RAPL: Add support for Ivy Bridge server
    (bsc#1003566).

  - powerpc/pseries: Use H_CLEAR_HPT to clear MMU hash table
    during kexec (bsc#1003813).

  - powerpc/xmon: Add xmon command to dump process/task
    similar to ps(1) (fate#322020).

  - proc: much faster /proc/vmstat (bnc#971975 VM
    performance -- vmstat).

  - qede: Correctly map aggregation replacement pages
    (bsc#966318 FATE#320158 bsc#966316 FATE#320159).

  - qed: FLR of active VFs might lead to FW assert
    (bsc#966318 FATE#320158 bsc#966316 FATE#320159).

  - qgroup: Prevent qgroup->reserved from going subzero
    (bsc#993841).

  - qla2xxx: Fix NULL pointer deref in QLA interrupt
    (bsc#1003068).

  - qla2xxx: setup data needed in ISR before setting up the
    ISR (bsc#1006528).

  - rbd: truncate objects on cmpext short reads
    (bsc#988715).

  - Revert 'ACPI / LPSS: allow to use specific PM domain
    during ->probe()' (bsc#1005917).

  - Revert 'can: dev: fix deadlock reported after bus-off'.

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

  - s390/mm: fix gmap tlb flush issues (bnc#1005925).

  - sched/core: Optimize __schedule() (bnc#978907 Scheduler
    performance -- context switch).

  - sched/fair: Fix incorrect task group ->load_avg
    (bsc#981825).

  - sched/fair: Optimize find_idlest_cpu() when there is no
    choice (bnc#978907 Scheduler performance -- idle
    search).

  - scsi: ibmvfc: Fix I/O hang when port is not mapped
    (bsc#971989)

  - serial: 8250_pci: Detach low-level driver during PCI
    error recovery (bsc#1013001).

  - serial: 8250_port: fix runtime PM use in
    __do_stop_tx_rs485() (bsc#983152).

  - sunrpc: fix refcounting problems with auth_gss messages
    (boo#1011250).

  - supported.conf: add hid-logitech-hidpp (bsc#1002322
    bsc#1002786)

  - supported.conf: Add overlay.ko to -base (fate#321903)
    Also, delete the stale entry for the old overlayfs.

  - supported.conf: Mark vmx-crypto as supported
    (fate#319564)

  - supported.conf: xen-netfront should be in base packages,
    just like its non-pvops predecessor. (bsc#1002770)

  - target: fix tcm_rbd_gen_it_nexus for emulated XCOPY
    state (bsc#1003606).

  - tg3: Avoid NULL pointer dereference in
    tg3_io_error_detected() (bsc#963609 FATE#320143).

  - time: Avoid undefined behaviour in ktime_add_safe()
    (bnc#1006103).

  - Update config files: select new
    CONFIG_SND_SOC_INTEL_SST_* helpers

  - Update
    patches.suse/btrfs-8401-fix-qgroup-accounting-when-creat
    ing-snap.patch (bsc#972993).

  - usb: gadget: composite: Clear reserved fields of SSP Dev
    Cap (FATE#319959).

  - usbhid: add ATEN CS962 to list of quirky devices
    (bsc#1007615).

  - usb: hub: Fix auto-remount of safely removed or ejected
    USB-3 devices (bsc#922634).

  - Using BUG_ON() as an assert() is _never_ acceptable
    (bnc#1005929).

  - vmxnet3: Wake queue from reset work (bsc#999907).

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

  - x86/hpet: Reduce HPET counter read contention
    (bsc#1014710).

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

  - x86/pci: VMD: Attach VMD resources to parent domain's
    resource tree (bsc#1006827).

  - x86/pci: VMD: Document code for maintainability
    (bsc#1006827).

  - x86/pci: VMD: Fix infinite loop executing irq's
    (bsc#1006827).

  - x86/pci: VMD: Initialize list item in IRQ disable
    (bsc#1006827).

  - x86/pci: VMD: Request userspace control of PCIe hotplug
    indicators (bsc#1006827).

  - x86/pci: VMD: Select device dma ops to override
    (bsc#1006827).

  - x86/pci: VMD: Separate MSI and MSI-X vector sharing
    (bsc#1006827).

  - x86/pci: VMD: Set bus resource start to 0 (bsc#1006827).

  - x86/pci: VMD: Synchronize with RCU freeing MSI IRQ descs
    (bsc#1006827).

  - x86/pci: VMD: Use lock save/restore in interrupt enable
    path (bsc#1006827).

  - x86/pci/VMD: Use untracked irq handler (bsc#1006827).

  - x86/pci: VMD: Use x86_vector_domain as parent domain
    (bsc#1006827).

  - x86, powercap, rapl: Add Skylake Server model number
    (bsc#1003566).

  - x86, powercap, rapl: Reorder CPU detection table
    (bsc#1003566).

  - x86, powercap, rapl: Use Intel model macros intead of
    open-coding (bsc#1003566).

  - xen/gntdev: Use VM_MIXEDMAP instead of VM_IO to avoid
    NUMA balancing (bnc#1005169).

  - zram: Fix unbalanced idr management at hot removal
    (bsc#1010970).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1000776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001310"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001486"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1001888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1002786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003964"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1004517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005921"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1005929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006103"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1006918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1007955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1008979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1009969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010158"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1010970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1013700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1014710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015359"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/799133"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/964462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966186"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/972993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974843"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/985850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/990384"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/993891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/994881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/995278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/997807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998054"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/998689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/999932"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8964.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7917.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8645.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-8666.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9793.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9919.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20170181-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c38ecfd4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12-SP2:zypper in -t patch
SUSE-SLE-WE-12-SP2-2017-87=1

SUSE Linux Enterprise Software Development Kit 12-SP2:zypper in -t
patch SUSE-SLE-SDK-12-SP2-2017-87=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-87=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-87=1

SUSE Linux Enterprise Live Patching 12:zypper in -t patch
SUSE-SLE-Live-Patching-12-2017-87=1

SUSE Linux Enterprise High Availability 12-SP2:zypper in -t patch
SUSE-SLE-HA-12-SP2-2017-87=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-87=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-base-debuginfo-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debuginfo-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-debugsource-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kernel-syms-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-debuginfo-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-debugsource-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-devel-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-4.4.38-93.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"kernel-syms-4.4.38-93.1")) flag++;


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
