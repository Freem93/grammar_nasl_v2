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
  script_id(70040);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/09/10 17:43:14 $");

  script_cve_id("CVE-2013-1059", "CVE-2013-1819", "CVE-2013-1929", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-3301", "CVE-2013-4162", "CVE-2013-4163");

  script_name(english:"SuSE 11.3 Security Update : Linux kernel (SAT Patch Numbers 8269 / 8270 / 8283)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel has been updated to
version 3.0.93 and to fix various bugs and security issues.

The following features have been added :

  - NFS: Now supports a 'nosharetransport' option
    (bnc#807502, bnc#828192, FATE#315593).

  - ALSA: virtuoso: Xonar DSX support was added
    (FATE#316016). The following security issues have been
    fixed :

  - The fill_event_metadata function in
    fs/notify/fanotify/fanotify_user.c in the Linux kernel
    did not initialize a certain structure member, which
    allowed local users to obtain sensitive information from
    kernel memory via a read operation on the fanotify
    descriptor. (CVE-2013-2148)

  - The key_notify_policy_flush function in net/key/af_key.c
    in the Linux kernel did not initialize a certain
    structure member, which allowed local users to obtain
    sensitive information from kernel heap memory by reading
    a broadcast message from the notify_policy interface of
    an IPSec key_socket. (CVE-2013-2237)

  - The ip6_sk_dst_check function in net/ipv6/ip6_output.c
    in the Linux kernel allowed local users to cause a
    denial of service (system crash) by using an AF_INET6
    socket for a connection to an IPv4 interface.
    (CVE-2013-2232)

  - The (1) key_notify_sa_flush and (2)
    key_notify_policy_flush functions in net/key/af_key.c in
    the Linux kernel did not initialize certain structure
    members, which allowed local users to obtain sensitive
    information from kernel heap memory by reading a
    broadcast message from the notify interface of an IPSec
    key_socket. CVE-2013-4162: The
    udp_v6_push_pending_frames function in net/ipv6/udp.c in
    the IPv6 implementation in the Linux kernel made an
    incorrect function call for pending data, which allowed
    local users to cause a denial of service (BUG and system
    crash) via a crafted application that uses the UDP_CORK
    option in a setsockopt system call. (CVE-2013-2234)

  - net/ceph/auth_none.c in the Linux kernel allowed remote
    attackers to cause a denial of service (NULL pointer
    dereference and system crash) or possibly have
    unspecified other impact via an auth_reply message that
    triggers an attempted build_request operation.
    (CVE-2013-1059)

  - The mmc_ioctl_cdrom_read_data function in
    drivers/cdrom/cdrom.c in the Linux kernel allowed local
    users to obtain sensitive information from kernel memory
    via a read operation on a malfunctioning CD-ROM drive.
    (CVE-2013-2164)

  - Format string vulnerability in the register_disk
    function in block/genhd.c in the Linux kernel allowed
    local users to gain privileges by leveraging root access
    and writing format string specifiers to
    /sys/module/md_mod/parameters/new_array in order to
    create a crafted /dev/md device name. (CVE-2013-2851)

  - The ip6_append_data_mtu function in
    net/ipv6/ip6_output.c in the IPv6 implementation in the
    Linux kernel did not properly maintain information about
    whether the IPV6_MTU setsockopt option had been
    specified, which allowed local users to cause a denial
    of service (BUG and system crash) via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call. (CVE-2013-4163)

  - Heap-based buffer overflow in the tg3_read_vpd function
    in drivers/net/ethernet/broadcom/tg3.c in the Linux
    kernel allowed physically proximate attackers to cause a
    denial of service (system crash) or possibly execute
    arbitrary code via crafted firmware that specifies a
    long string in the Vital Product Data (VPD) data
    structure. (CVE-2013-1929)

  - The _xfs_buf_find function in fs/xfs/xfs_buf.c in the
    Linux kernel did not validate block numbers, which
    allowed local users to cause a denial of service (NULL
    pointer dereference and system crash) or possibly have
    unspecified other impact by leveraging the ability to
    mount an XFS filesystem containing a metadata inode with
    an invalid extent map. (CVE-2013-1819)

Also the following non-security bugs have been fixed :

  - ACPI / APEI: Force fatal AER severity when component has
    been reset. (bnc#828886 / bnc#824568)

  - PCI/AER: Move AER severity defines to aer.h. (bnc#828886
    / bnc#824568)

  - PCI/AER: Set dev->__aer_firmware_first only for matching
    devices. (bnc#828886 / bnc#824568)

  - PCI/AER: Factor out HEST device type matching.
    (bnc#828886 / bnc#824568)

  - PCI/AER: Do not parse HEST table for non-PCIe devices.
    (bnc#828886 / bnc#824568)

  - PCI/AER: Reset link for devices below Root Port or
    Downstream Port. (bnc#828886 / bnc#824568)

  - zfcp: fix lock imbalance by reworking request queue
    locking (bnc#835175, LTC#96825).

  - qeth: Fix crash on initial MTU size change (bnc#835175,
    LTC#96809).

  - qeth: change default standard blkt settings for OSA
    Express (bnc#835175, LTC#96808).

  - x86: Add workaround to NMI iret woes. (bnc#831949)

  - x86: Do not schedule while still in NMI context.
    (bnc#831949)

  - drm/i915: no longer call drm_helper_resume_force_mode.
    (bnc#831424,bnc#800875)

  - bnx2x: protect different statistics flows. (bnc#814336)

  - bnx2x: Avoid sending multiple statistics queries.
    (bnc#814336)

  - bnx2x: protect different statistics flows. (bnc#814336)

  - ALSA: hda - Fix unbalanced runtime pm refount.
    (bnc#834742)

  - xhci: directly calling _PS3 on suspend. (bnc#833148)

  - futex: Take hugepages into account when generating
    futex_key.

  - e1000e: workaround DMA unit hang on I218. (bnc#834647)

  - e1000e: unexpected 'Reset adapter' message when cable
    pulled. (bnc#834647)

  - e1000e: 82577: workaround for link drop issue.
    (bnc#834647)

  - e1000e: helper functions for accessing EMI registers.
    (bnc#834647)

  - e1000e: workaround DMA unit hang on I218. (bnc#834647)

  - e1000e: unexpected 'Reset adapter' message when cable
    pulled. (bnc#834647)

  - e1000e: 82577: workaround for link drop issue.
    (bnc#834647)

  - e1000e: helper functions for accessing EMI registers.
    (bnc#834647)

  - Drivers: hv: util: Fix a bug in version negotiation code
    for util services. (bnc#828714)

  - printk: Add NMI ringbuffer. (bnc#831949)

  - printk: extract ringbuffer handling from vprintk.
    (bnc#831949)

  - printk: NMI safe printk. (bnc#831949)

  - printk: Make NMI ringbuffer size independent on
    log_buf_len. (bnc#831949)

  - printk: Do not call console_unlock from nmi context.
    (bnc#831949)

  - printk: Do not use printk_cpu from finish_printk.
    (bnc#831949)

  - zfcp: fix schedule-inside-lock in scsi_device list loops
    (bnc#833073, LTC#94937).

  - uvc: increase number of buffers. (bnc#822164,
    bnc#805804)

  - drm/i915: Adding more reserved PCI IDs for Haswell.
    (bnc#834116)

  - Refresh patches.xen/xen-netback-generalize. (bnc#827378)

  - Update Xen patches to 3.0.87.

  - mlx4_en: Adding 40gb speed report for ethtool.
    (bnc#831410)

  - drm/i915: Retry DP aux_ch communications with a
    different clock after failure. (bnc#831422)

  - drm/i915: split aux_clock_divider logic in a separated
    function for reuse. (bnc#831422)

  - drm/i915: dp: increase probe retries. (bnc#831422)

  - drm/i915: Only clear write-domains after a successful
    wait-seqno. (bnc#831422)

  - drm/i915: Fix write-read race with multiple rings.
    (bnc#831422)

  - drm/i915: Retry DP aux_ch communications with a
    different clock after failure. (bnc#831422)

  - drm/i915: split aux_clock_divider logic in a separated
    function for reuse. (bnc#831422)

  - drm/i915: dp: increase probe retries. (bnc#831422)

  - drm/i915: Only clear write-domains after a successful
    wait-seqno. (bnc#831422)

  - drm/i915: Fix write-read race with multiple rings.
    (bnc#831422)

  - xhci: Add xhci_disable_ports boot option. (bnc#822164)

  - xhci: set device to D3Cold on shutdown. (bnc#833097)

  - reiserfs: Fixed double unlock in reiserfs_setattr
    failure path.

  - reiserfs: locking, release lock around quota operations.
    (bnc#815320)

  - reiserfs: locking, push write lock out of xattr code.
    (bnc#815320)

  - reiserfs: locking, handle nested locks properly.
    (bnc#815320)

  - reiserfs: do not lock journal_init(). (bnc#815320)

  - reiserfs: delay reiserfs lock until journal
    initialization. (bnc#815320)

  - NFS: support 'nosharetransport' option (bnc#807502,
    bnc#828192, FATE#315593).

  - HID: hyperv: convert alloc+memcpy to memdup.

  - Drivers: hv: vmbus: Implement multi-channel support
    (fate#316098).

  - Drivers: hv: Add the GUID fot synthetic fibre channel
    device (fate#316098).

  - tools: hv: Check return value of setsockopt call.

  - tools: hv: Check return value of poll call.

  - tools: hv: Check return value of strchr call.

  - tools: hv: Fix file descriptor leaks.

  - tools: hv: Improve error logging in KVP daemon.

  - drivers: hv: switch to use mb() instead of smp_mb().

  - drivers: hv: check interrupt mask before read_index.

  - drivers: hv: allocate synic structures before
    hv_synic_init().

  - storvsc: Increase the value of scsi timeout for storvsc
    devices (fate#316098).

  - storvsc: Update the storage protocol to win8 level
    (fate#316098).

  - storvsc: Implement multi-channel support (fate#316098).

  - storvsc: Support FC devices (fate#316098).

  - storvsc: Increase the value of STORVSC_MAX_IO_REQUESTS
    (fate#316098).

  - hyperv: Fix the NETIF_F_SG flag setting in netvsc.

  - Drivers: hv: vmbus: incorrect device name is printed
    when child device is unregistered.

  - Tools: hv: KVP: Fix a bug in IPV6 subnet enumeration.
    (bnc#828714)

  - ipv6: ip6_append_data_mtu did not care about pmtudisc
    and frag_size. (bnc#831055, CVE-2013-4163)

  - ipv6: ip6_append_data_mtu did not care about pmtudisc
    and frag_size. (bnc#831055, CVE-2013-4163)

  - dm mpath: add retain_attached_hw_handler feature.
    (bnc#760407)

  - scsi_dh: add scsi_dh_attached_handler_name. (bnc#760407)

  - af_key: fix info leaks in notify messages. (bnc#827749 /
    CVE-2013-2234)

  - af_key: initialize satype in key_notify_policy_flush().
    (bnc#828119 / CVE-2013-2237)

  - ipv6: call udp_push_pending_frames when uncorking a
    socket with. (bnc#831058, CVE-2013-4162)

  - tg3: fix length overflow in VPD firmware parsing.
    (bnc#813733 / CVE-2013-1929)

  - xfs: fix _xfs_buf_find oops on blocks beyond the
    filesystem end. (CVE-2013-1819 / bnc#807471)

  - ipv6: ip6_sk_dst_check() must not assume ipv6 dst.
    (bnc#827750, CVE-2013-2232)

  - dasd: fix hanging devices after path events (bnc#831623,
    LTC#96336).

  - kernel: z90crypt module load crash (bnc#831623,
    LTC#96214).

  - ata: Fix DVD not detected at some platform with
    Wellsburg PCH. (bnc#822225)

  - drm/i915: edp: add standard modes. (bnc#832318)

  - Do not switch camera on yet more HP machines.
    (bnc#822164)

  - Do not switch camera on HP EB 820 G1. (bnc#822164)

  - xhci: Avoid NULL pointer deref when host dies.
    (bnc#827271)

  - bonding: disallow change of MAC if fail_over_mac
    enabled. (bnc#827376)

  - bonding: propagate unicast lists down to slaves.
    (bnc#773255 / bnc#827372)

  - net/bonding: emit address change event also in
    bond_release. (bnc#773255 / bnc#827372)

  - bonding: emit event when bonding changes MAC.
    (bnc#773255 / bnc#827372)

  - usb: host: xhci: Enable XHCI_SPURIOUS_SUCCESS for all
    controllers with xhci 1.0. (bnc#797909)

  - xhci: fix NULL pointer dereference on
    ring_doorbell_for_active_rings. (bnc#827271)

  - updated reference for security issue fixed inside.
    (CVE-2013-3301 / bnc#815256)

  - qla2xxx: Clear the MBX_INTR_WAIT flag when the mailbox
    time-out happens. (bnc#830478)

  - drm/i915: initialize gt_lock early with other spin
    locks. (bnc#801341)

  - drm/i915: fix up gt init sequence fallout. (bnc#801341)

  - drm/i915: initialize gt_lock early with other spin
    locks. (bnc#801341)

  - drm/i915: fix up gt init sequence fallout. (bnc#801341)

  - timer_list: Correct the iterator for timer_list.
    (bnc#818047)

  - firmware: do not spew errors in normal boot (bnc#831438,
    fate#314574).

  - ALSA: virtuoso: Xonar DSX support (FATE#316016).

  - SUNRPC: Ensure we release the socket write lock if the
    rpc_task exits early. (bnc#830901)

  - ext4: Re-add config option Building ext4 as the
    ext4-writeable KMP uses CONFIG_EXT4_FS_RW=y to denote
    that read-write module should be enabled. This update
    just defaults allow_rw to true if it is set.

  - e1000: fix vlan processing regression. (bnc#830766)

  - ext4: force read-only unless rw=1 module option is used
    (fate#314864).

  - dm mpath: fix ioctl deadlock when no paths. (bnc#808940)

  - HID: fix unused rsize usage. (bnc#783475)

  - add reference for b43 format string flaw. (bnc#822579 /
    CVE-2013-2852)

  - HID: fix data access in implement(). (bnc#783475)

  - xfs: fix deadlock in xfs_rtfree_extent with kernel v3.x.
    (bnc#829622)

  - kernel: sclp console hangs (bnc#830346, LTC#95711).

  - Refresh
    patches.fixes/rtc-add-an-alarm-disable-quirk.patch.

  - Delete
    patches.drm/1209-nvc0-fb-shut-up-pmfb-interrupt-after-th
    e-first-occurrence. It was removed from series.conf in
    063ed686e5a3cda01a7ddbc49db1499da917fef5 but the file
    was not deleted.

  - Drivers: hv: balloon: Do not post pressure status if
    interrupted. (bnc#829539)

  - Drivers: hv: balloon: Fix a bug in the hot-add code.
    (bnc#829539)

  - drm/i915: Fix incoherence with fence updates on
    Sandybridge+. (bnc#809463)

  - drm/i915: merge {i965, sandybridge}_write_fence_reg().
    (bnc#809463)

  - drm/i915: Fix incoherence with fence updates on
    Sandybridge+. (bnc#809463)

  - drm/i915: merge {i965, sandybridge}_write_fence_reg().
    (bnc#809463)

  - Refresh
    patches.fixes/rtc-add-an-alarm-disable-quirk.patch.

  - r8169: allow multicast packets on sub-8168f chipset.
    (bnc#805371)

  - r8169: support new chips of RTL8111F. (bnc#805371)

  - r8169: define the early size for 8111evl. (bnc#805371)

  - r8169: fix the reset setting for 8111evl. (bnc#805371)

  - r8169: add MODULE_FIRMWARE for the firmware of 8111evl.
    (bnc#805371)

  - r8169: fix sticky accepts packet bits in RxConfig.
    (bnc#805371)

  - r8169: adjust the RxConfig settings. (bnc#805371)

  - r8169: support RTL8111E-VL. (bnc#805371)

  - r8169: add ERI functions. (bnc#805371)

  - r8169: modify the flow of the hw reset. (bnc#805371)

  - r8169: adjust some registers. (bnc#805371)

  - r8169: check firmware content sooner. (bnc#805371)

  - r8169: support new firmware format. (bnc#805371)

  - r8169: explicit firmware format check. (bnc#805371)

  - r8169: move the firmware down into the device private
    data. (bnc#805371)

  - r8169: allow multicast packets on sub-8168f chipset.
    (bnc#805371)

  - r8169: support new chips of RTL8111F. (bnc#805371)

  - r8169: define the early size for 8111evl. (bnc#805371)

  - r8169: fix the reset setting for 8111evl. (bnc#805371)

  - r8169: add MODULE_FIRMWARE for the firmware of 8111evl.
    (bnc#805371)

  - r8169: fix sticky accepts packet bits in RxConfig.
    (bnc#805371)

  - r8169: adjust the RxConfig settings. (bnc#805371)

  - r8169: support RTL8111E-VL. (bnc#805371)

  - r8169: add ERI functions. (bnc#805371)

  - r8169: modify the flow of the hw reset. (bnc#805371)

  - r8169: adjust some registers. (bnc#805371)

  - r8169: check firmware content sooner. (bnc#805371)

  - r8169: support new firmware format. (bnc#805371)

  - r8169: explicit firmware format check. (bnc#805371)

  - r8169: move the firmware down into the device private
    data. (bnc#805371)

  -
    patches.fixes/mm-link_mem_sections-touch-nmi-watchdog.pa
    tch: mm: link_mem_sections make sure nmi watchdog does
    not trigger while linking memory sections. (bnc#820434)

  - drm/i915: fix long-standing SNB regression in power
    consumption after resume v2. (bnc#801341)

  - RTC: Add an alarm disable quirk. (bnc#805740)

  - drm/i915: Fix bogus hotplug warnings at resume.
    (bnc#828087)

  - drm/i915: Serialize all register access.
    (bnc#809463,bnc#812274,bnc#822878,bnc#828914)

  - drm/i915: Resurrect ring kicking for semaphores,
    selectively. (bnc#828087)

  - drm/i915: Fix bogus hotplug warnings at resume.
    (bnc#828087)

  - drm/i915: Serialize all register access.
    (bnc#809463,bnc#812274,bnc#822878,bnc#828914)

  - drm/i915: Resurrect ring kicking for semaphores,
    selectively. (bnc#828087)

  - drm/i915: use lower aux clock divider on non-ULT HSW.
    (bnc#800875)

  - drm/i915: preserve the PBC bits of TRANS_CHICKEN2.
    (bnc#828087)

  - drm/i915: set CPT FDI RX polarity bits based on VBT.
    (bnc#828087)

  - drm/i915: hsw: fix link training for eDP on port-A.
    (bnc#800875)

  - drm/i915: use lower aux clock divider on non-ULT HSW.
    (bnc#800875)

  - drm/i915: preserve the PBC bits of TRANS_CHICKEN2.
    (bnc#828087)

  - drm/i915: set CPT FDI RX polarity bits based on VBT.
    (bnc#828087)

  - drm/i915: hsw: fix link training for eDP on port-A.
    (bnc#800875)

  - patches.arch/s390-66-02-smp-ipi.patch: kernel: lost IPIs
    on CPU hotplug (bnc#825048, LTC#94784).

  -
    patches.fixes/iwlwifi-use-correct-supported-firmware-for
    -6035-and-.patch: iwlwifi: use correct supported
    firmware for 6035 and 6000g2. (bnc#825887)

  -
    patches.fixes/watchdog-update-watchdog_thresh-atomically
    .patch: watchdog: Update watchdog_thresh atomically.
    (bnc#829357)

  -
    patches.fixes/watchdog-update-watchdog_tresh-properly.pa
    tch: watchdog: update watchdog_tresh properly.
    (bnc#829357)

  -
    patches.fixes/watchdog-make-disable-enable-hotplug-and-p
    reempt-save.patch:
    watchdog-make-disable-enable-hotplug-and-preempt-save.pa
    tch. (bnc#829357)

  - kabi/severities: Ignore changes in drivers/hv

  -
    patches.drivers/lpfc-return-correct-error-code-on-bsg_ti
    meout.patch: lpfc: Return correct error code on
    bsg_timeout. (bnc#816043)

  -
    patches.fixes/dm-drop-table-reference-on-ioctl-retry.pat
    ch: dm-multipath: Drop table when retrying ioctl.
    (bnc#808940)

  - scsi: Do not retry invalid function error. (bnc#809122)

  -
    patches.suse/scsi-do-not-retry-invalid-function-error.pa
    tch: scsi: Do not retry invalid function error.
    (bnc#809122)

  - scsi: Always retry internal target error. (bnc#745640,
    bnc#825227)

  -
    patches.suse/scsi-always-retry-internal-target-error.pat
    ch: scsi: Always retry internal target error.
    (bnc#745640, bnc#825227)

  -
    patches.drivers/drm-edid-Don-t-print-messages-regarding-
    stereo-or-csync-by-default.patch: Refresh: add upstream
    commit ID.

  - patches.suse/acpiphp-match-to-Bochs-dmi-data.patch:
    Refresh. . (bnc#824915)

  - Refresh
    patches.suse/acpiphp-match-to-Bochs-dmi-data.patch.
    (bnc#824915)

  - Update kabi files.

  - ACPI:remove panic in case hardware has changed after S4.
    (bnc#829001)

  - ibmvfc: Driver version 1.0.1. (bnc#825142)

  - ibmvfc: Fix for offlining devices during error recovery.
    (bnc#825142)

  - ibmvfc: Properly set cancel flags when cancelling abort.
    (bnc#825142)

  - ibmvfc: Send cancel when link is down. (bnc#825142)

  - ibmvfc: Support FAST_IO_FAIL in EH handlers.
    (bnc#825142)

  - ibmvfc: Suppress ABTS if target gone. (bnc#825142)

  - fs/dcache.c: add cond_resched() to
    shrink_dcache_parent(). (bnc#829082)

  - drivers/cdrom/cdrom.c: use kzalloc() for failing
    hardware. (bnc#824295, CVE-2013-2164)

  - kmsg_dump: do not run on non-error paths by default.
    (bnc#820172)

  - supported.conf: mark tcm_qla2xxx as supported

  - mm: honor min_free_kbytes set by user. (bnc#826960)

  - Drivers: hv: util: Fix a bug in version negotiation code
    for util services. (bnc#828714)

  - hyperv: Fix a kernel warning from
    netvsc_linkstatus_callback(). (bnc#828574)

  - RT: Fix up hardening patch to not gripe when avg >
    available, which lockless access makes possible and
    happens in -rt kernels running a cpubound ltp realtime
    testcase. Just keep the output sane in that case.

  - kabi/severities: Add exception for aer_recover_queue()
    There should not be any user besides ghes.ko.

  - Fix rpm changelog

  - PCI / PM: restore the original behavior of
    pci_set_power_state(). (bnc#827930)

  - fanotify: info leak in copy_event_to_user().
    (CVE-2013-2148 / bnc#823517)

  - usb: xhci: check usb2 port capabilities before adding hw
    link PM support. (bnc#828265)

  - aerdrv: Move cper_print_aer() call out of interrupt
    context. (bnc#822052, bnc#824568)

  - PCI/AER: pci_get_domain_bus_and_slot() call missing
    required pci_dev_put(). (bnc#822052, bnc#824568)

  -
    patches.fixes/block-do-not-pass-disk-names-as-format-str
    ings.patch: block: do not pass disk names as format
    strings. (bnc#822575 / CVE-2013-2851)

  - powerpc: POWER8 cputable entries. (bnc#824256)

  - libceph: Fix NULL pointer dereference in auth client
    code. (CVE-2013-1059, bnc#826350)

  - md/raid10: Fix two bug affecting RAID10 reshape.

  - Allow NFSv4 to run execute-only files. (bnc#765523)

  - fs/ocfs2/namei.c: remove unnecessary ERROR when removing
    non-empty directory. (bnc#819363)

  - block: Reserve only one queue tag for sync IO if only 3
    tags are available. (bnc#806396)

  - btrfs: merge contiguous regions when loading free space
    cache

  - btrfs: fix how we deal with the orphan block rsv.

  - btrfs: fix wrong check during log recovery.

  - btrfs: change how we indicate we are adding csums."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=760407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=783475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=789010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=797909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=800875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=801341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805740"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=805804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=806396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=807502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=812274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=813733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=814336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=815320"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=816043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=818047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=819363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822164"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=822878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=823517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824295"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=824915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=825887"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=826960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827372"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827750"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827930"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828119"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829001"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=829622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=830901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831055"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831438"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=831949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=832318"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833097"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1059.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1819.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2234.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2237.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2852.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-3301.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4162.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4163.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 8269 / 8270 / 8283 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-extra-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-extra-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-source-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-syms-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-trace-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-extra-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.2_06_3.0.93_0.8-0.7.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.2_06_3.0.93_0.8-0.7.17")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.2_06_3.0.93_0.8-0.7.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-source-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-syms-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.2_06_3.0.93_0.8-0.7.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.2_06_3.0.93_0.8-0.7.17")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kernel-default-man-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.93-0.8.2")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.2_06_3.0.93_0.8-0.7.17")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
