#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1015.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(93104);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2012-6701", "CVE-2013-7446", "CVE-2014-9904", "CVE-2015-3288", "CVE-2015-6526", "CVE-2015-7566", "CVE-2015-8709", "CVE-2015-8785", "CVE-2015-8812", "CVE-2015-8816", "CVE-2015-8830", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-2184", "CVE-2016-2185", "CVE-2016-2186", "CVE-2016-2187", "CVE-2016-2188", "CVE-2016-2384", "CVE-2016-2543", "CVE-2016-2544", "CVE-2016-2545", "CVE-2016-2546", "CVE-2016-2547", "CVE-2016-2548", "CVE-2016-2549", "CVE-2016-2782", "CVE-2016-2847", "CVE-2016-3134", "CVE-2016-3136", "CVE-2016-3137", "CVE-2016-3138", "CVE-2016-3139", "CVE-2016-3140", "CVE-2016-3156", "CVE-2016-3672", "CVE-2016-3689", "CVE-2016-3951", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4581", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-5244", "CVE-2016-5829");

  script_name(english:"openSUSE Security Update : the Linux Kernel (openSUSE-2016-1015)");
  script_summary(english:"Check for the openSUSE-2016-1015 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 13.2 kernel was updated to fix various bugs and security
issues.

The following security bugs were fixed :

  - CVE-2016-1583: Prevent the usage of mmap when the lower
    file system does not allow it. This could have lead to
    local privilege escalation when ecryptfs-utils was
    installed and /sbin/mount.ecryptfs_private was setuid
    (bsc#983143).

  - CVE-2016-4913: The get_rock_ridge_filename function in
    fs/isofs/rock.c in the Linux kernel mishandles NM (aka
    alternate name) entries containing \0 characters, which
    allowed local users to obtain sensitive information from
    kernel memory or possibly have unspecified other impact
    via a crafted isofs filesystem (bnc#980725).

  - CVE-2016-4580: The x25_negotiate_facilities function in
    net/x25/x25_facilities.c in the Linux kernel did not
    properly initialize a certain data structure, which
    allowed attackers to obtain sensitive information from
    kernel stack memory via an X.25 Call Request
    (bnc#981267).

  - CVE-2016-0758: Tags with indefinite length could have
    corrupted pointers in asn1_find_indefinite_length
    (bsc#979867).

  - CVE-2016-2053: The asn1_ber_decoder function in
    lib/asn1_decoder.c in the Linux kernel allowed attackers
    to cause a denial of service (panic) via an ASN.1 BER
    file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in
    crypto/asymmetric_keys/public_key.c (bnc#963762).

  - CVE-2016-2187: The gtco_probe function in
    drivers/input/tablet/gtco.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#971919 971944).

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bnc#978401 bsc#978445).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relies on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548 bsc#980363).

  - CVE-2016-3672: The arch_pick_mmap_layout function in
    arch/x86/mm/mmap.c in the Linux kernel did not properly
    randomize the legacy base address, which made it easier
    for local users to defeat the intended restrictions on
    the ADDR_NO_RANDOMIZE flag, and bypass the ASLR
    protection mechanism for a setuid or setgid program, by
    disabling stack-consumption resource limits
    (bnc#974308).

  - CVE-2016-4581: fs/pnode.c in the Linux kernel did not
    properly traverse a mount propagation tree in a certain
    case involving a slave mount, which allowed local users
    to cause a denial of service (NULL pointer dereference
    and OOPS) via a crafted series of mount system calls
    (bnc#979913).

  - CVE-2016-4485: The llc_cmsg_rcv function in
    net/llc/af_llc.c in the Linux kernel did not initialize
    a certain data structure, which allowed attackers to
    obtain sensitive information from kernel stack memory by
    reading a message (bnc#978821).

  - CVE-2015-3288: A security flaw was found in the Linux
    kernel that there was a way to arbitrary change zero
    page memory. (bnc#979021).

  - CVE-2016-4578: sound/core/timer.c in the Linux kernel
    did not initialize certain r1 data structures, which
    allowed local users to obtain sensitive information from
    kernel stack memory via crafted use of the ALSA timer
    interface, related to the (1) snd_timer_user_ccallback
    and (2) snd_timer_user_tinterrupt functions
    (bnc#979879).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126).

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

  - CVE-2013-7446: Use-after-free vulnerability in
    net/unix/af_unix.c in the Linux kernel allowed local
    users to bypass intended AF_UNIX socket permissions or
    cause a denial of service (panic) via crafted epoll_ctl
    calls (bnc#955654).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bnc#979213).

  - CVE-2016-2847: fs/pipe.c in the Linux kernel did not
    limit the amount of unread data in pipes, which allowed
    local users to cause a denial of service (memory
    consumption) by creating many pipes with non-default
    sizes (bnc#970948 974646).

  - CVE-2016-3136: The mct_u232_msr_to_state function in
    drivers/usb/serial/mct_u232.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted USB device without two interrupt-in
    endpoint descriptors (bnc#970955).

  - CVE-2016-2188: The iowarrior_probe function in
    drivers/usb/misc/iowarrior.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#970956).

  - CVE-2016-3138: The acm_probe function in
    drivers/usb/class/cdc-acm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a USB device without both a control and a data endpoint
    descriptor (bnc#970911).

  - CVE-2016-3137: drivers/usb/serial/cypress_m8.c in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference and
    system crash) via a USB device without both an
    interrupt-in and an interrupt-out endpoint descriptor,
    related to the cypress_generic_port_probe and
    cypress_open functions (bnc#970970).

  - CVE-2016-3951: Double free vulnerability in
    drivers/net/usb/cdc_ncm.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) or possibly have unspecified
    other impact by inserting a USB device with an invalid
    USB descriptor (bnc#974418).

  - CVE-2016-3140: The digi_port_init function in
    drivers/usb/serial/digi_acceleport.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970892).

  - CVE-2016-2186: The powermate_probe function in
    drivers/input/misc/powermate.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970958).

  - CVE-2016-2185: The ati_remote2_probe function in
    drivers/input/misc/ati_remote2.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#971124).

  - CVE-2016-3689: The ims_pcu_parse_cdc_data function in
    drivers/input/misc/ims-pcu.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (system crash) via a USB device without both a
    master and a slave interface (bnc#971628).

  - CVE-2016-3156: The IPv4 implementation in the Linux
    kernel mishandles destruction of device objects, which
    allowed guest OS users to cause a denial of service
    (host OS networking outage) by arranging for a large
    number of IP addresses (bnc#971360).

  - CVE-2016-2184: The create_fixed_stream_quirk function in
    sound/usb/quirks.c in the snd-usb-audio driver in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (NULL pointer dereference or
    double free, and system crash) via a crafted endpoints
    value in a USB device descriptor (bnc#971125).

  - CVE-2016-3139: The wacom_probe function in
    drivers/input/tablet/wacom_sys.c in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and system crash)
    via a crafted endpoints value in a USB device descriptor
    (bnc#970909).

  - CVE-2015-8830: Integer overflow in the
    aio_setup_single_vector function in fs/aio.c in the
    Linux kernel 4.0 allowed local users to cause a denial
    of service or possibly have unspecified other impact via
    a large AIO iovec. NOTE: this vulnerability exists
    because of a CVE-2012-6701 regression (bnc#969354
    bsc#969355).

  - CVE-2016-2782: The treo_attach function in
    drivers/usb/serial/visor.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact by inserting a
    USB device that lacks a (1) bulk-in or (2) interrupt-in
    endpoint (bnc#968670).

  - CVE-2015-8816: The hub_activate function in
    drivers/usb/core/hub.c in the Linux kernel did not
    properly maintain a hub-interface data structure, which
    allowed physically proximate attackers to cause a denial
    of service (invalid memory access and system crash) or
    possibly have unspecified other impact by unplugging a
    USB hub device (bnc#968010).

  - CVE-2015-7566: The clie_5_attach function in
    drivers/usb/serial/visor.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) or
    possibly have unspecified other impact by inserting a
    USB device that lacks a bulk-out endpoint (bnc#961512).

  - CVE-2016-2549: sound/core/hrtimer.c in the Linux kernel
    did not prevent recursive callback access, which allowed
    local users to cause a denial of service (deadlock) via
    a crafted ioctl call (bnc#968013).

  - CVE-2016-2547: sound/core/timer.c in the Linux kernel
    employs a locking approach that did not consider slave
    timer instances, which allowed local users to cause a
    denial of service (race condition, use-after-free, and
    system crash) via a crafted ioctl call (bnc#968011).

  - CVE-2016-2548: sound/core/timer.c in the Linux kernel
    retains certain linked lists after a close or stop
    action, which allowed local users to cause a denial of
    service (system crash) via a crafted ioctl call, related
    to the (1) snd_timer_close and (2) _snd_timer_stop
    functions (bnc#968012).

  - CVE-2016-2546: sound/core/timer.c in the Linux kernel
    uses an incorrect type of mutex, which allowed local
    users to cause a denial of service (race condition,
    use-after-free, and system crash) via a crafted ioctl
    call (bnc#967975).

  - CVE-2016-2545: The snd_timer_interrupt function in
    sound/core/timer.c in the Linux kernel did not properly
    maintain a certain linked list, which allowed local
    users to cause a denial of service (race condition and
    system crash) via a crafted ioctl call (bnc#967974).

  - CVE-2016-2544: Race condition in the queue_delete
    function in sound/core/seq/seq_queue.c in the Linux
    kernel allowed local users to cause a denial of service
    (use-after-free and system crash) by making an ioctl
    call at a certain time (bnc#967973).

  - CVE-2016-2543: The snd_seq_ioctl_remove_events function
    in sound/core/seq/seq_clientmgr.c in the Linux kernel
    did not verify FIFO assignment before proceeding with
    FIFO clearing, which allowed local users to cause a
    denial of service (NULL pointer dereference and OOPS)
    via a crafted ioctl call (bnc#967972).

  - CVE-2015-8709: ** DISPUTED ** kernel/ptrace.c in the
    Linux kernel mishandles uid and gid mappings, which
    allowed local users to gain privileges by establishing a
    user namespace, waiting for a root process to enter that
    namespace with an unsafe uid or gid, and then using the
    ptrace system call. NOTE: the vendor states 'there is no
    kernel bug here (bnc#959709 960561 ).

  - CVE-2015-8812: drivers/infiniband/hw/cxgb3/iwch_cm.c in
    the Linux kernel did not properly identify error
    conditions, which allowed remote attackers to execute
    arbitrary code or cause a denial of service
    (use-after-free) via crafted packets (bnc#966437).

  - CVE-2016-2384: Double free vulnerability in the
    snd_usbmidi_create function in sound/usb/midi.c in the
    Linux kernel allowed physically proximate attackers to
    cause a denial of service (panic) or possibly have
    unspecified other impact via vectors involving an
    invalid USB descriptor (bnc#966693).

  - CVE-2015-8785: The fuse_fill_write_pages function in
    fs/fuse/file.c in the Linux kernel allowed local users
    to cause a denial of service (infinite loop) via a
    writev system call that triggers a zero length for the
    first segment of an iov (bnc#963765).

  - CVE-2014-9904: The snd_compress_check_input function in
    sound/core/compress_offload.c in the ALSA subsystem in
    the Linux kernel did not properly check for an integer
    overflow, which allowed local users to cause a denial of
    service (insufficient memory allocation) or possibly
    have unspecified other impact via a crafted
    SNDRV_COMPRESS_SET_PARAMS ioctl call (bnc#986811).

  - CVE-2016-5829: Multiple heap-based buffer overflows in
    the hiddev_ioctl_usage function in
    drivers/hid/usbhid/hiddev.c in the Linux kernel allow
    local users to cause a denial of service or possibly
    have unspecified other impact via a crafted (1)
    HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call
    (bnc#986572 986573).

  - CVE-2016-4997: The compat IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to gain privileges or cause a
    denial of service (memory corruption) by leveraging
    in-container root access to provide a crafted offset
    value that triggers an unintended decrement (bnc#986362
    986365 986377).

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions (bnc#980371).

  - CVE-2016-4470: The key_reject_and_link function in
    security/keys/key.c in the Linux kernel did not ensure
    that a certain data structure is initialized, which
    allowed local users to cause a denial of service (system
    crash) via vectors involving a crafted keyctl request2
    command (bnc#984755 984764).

  - CVE-2015-6526: The perf_callchain_user_64 function in
    arch/powerpc/perf/callchain.c in the Linux kernel on
    ppc64 platforms allowed local users to cause a denial of
    service (infinite loop) via a deep 64-bit userspace
    backtrace (bnc#942702).

  - CVE-2016-5244: The rds_inc_info_copy function in
    net/rds/recv.c in the Linux kernel did not initialize a
    certain structure member, which allowed remote attackers
    to obtain sensitive information from kernel stack memory
    by reading an RDS message (bnc#983213).

The following non-security bugs were fixed :

  - ALSA: hrtimer: Handle start/stop more properly
    (bsc#973378).

  - ALSA: pcm: Fix potential deadlock in OSS emulation
    (bsc#968018).

  - ALSA: rawmidi: Fix race at copying & updating the
    position (bsc#968018).

  - ALSA: rawmidi: Make snd_rawmidi_transmit() race-free
    (bsc#968018).

  - ALSA: seq: Fix double port list deletion (bsc#968018).

  - ALSA: seq: Fix incorrect sanity check at
    snd_seq_oss_synth_cleanup() (bsc#968018).

  - ALSA: seq: Fix leak of pool buffer at concurrent writes
    (bsc#968018).

  - ALSA: seq: Fix lockdep warnings due to double mutex
    locks (bsc#968018).

  - ALSA: seq: Fix race at closing in virmidi driver
    (bsc#968018).

  - ALSA: seq: Fix yet another races among ALSA timer
    accesses (bsc#968018).

  - ALSA: timer: Call notifier in the same spinlock
    (bsc#973378).

  - ALSA: timer: Code cleanup (bsc#968018).

  - ALSA: timer: Fix leftover link at closing (bsc#968018).

  - ALSA: timer: Fix link corruption due to double start or
    stop (bsc#968018).

  - ALSA: timer: Fix race between stop and interrupt
    (bsc#968018).

  - ALSA: timer: Fix wrong instance passed to slave
    callbacks (bsc#968018).

  - ALSA: timer: Protect the whole snd_timer_close() with
    open race (bsc#973378).

  - ALSA: timer: Sync timer deletion at closing the system
    timer (bsc#973378).

  - ALSA: timer: Use mod_timer() for rearming the system
    timer (bsc#973378).

  - Bluetooth: vhci: Fix race at creating hci device
    (bsc#971799,bsc#966849).

  - Bluetooth: vhci: fix open_timeout vs. hdev race
    (bsc#971799,bsc#966849).

  - Bluetooth: vhci: purge unhandled skbs
    (bsc#971799,bsc#966849).

  - Btrfs: do not use src fd for printk (bsc#980348).

  - Refresh
    patches.drivers/ALSA-hrtimer-Handle-start-stop-more-prop
    erly. Fix the build error on 32bit architectures.

  - Refresh patches.xen/xen-netback-coalesce: Restore
    copying of SKBs with head exceeding page size
    (bsc#978469).

  - Refresh patches.xen/xen3-patch-3.14: Suppress atomic
    file position updates on /proc/xen/xenbus (bsc#970275).

  - Subject: [PATCH] USB: xhci: Add broken streams quirk for
    Frescologic device id 1009 (bnc#982706).

  - USB: usbip: fix potential out-of-bounds write
    (bnc#975945).

  - af_unix: Guard against other == sk in unix_dgram_sendmsg
    (bsc#973570).

  - backends: guarantee one time reads of shared ring
    contents (bsc#957988).

  - btrfs: do not go readonly on existing qgroup items
    (bsc#957052).

  - btrfs: remove error message from search ioctl for
    nonexistent tree.

  - drm/i915: Fix missing backlight update during panel
    disablement (bsc#941113 boo#901754).

  - enic: set netdev->vlan_features (bsc#966245).

  - ext4: fix races between buffered IO and collapse /
    insert range (bsc#972174).

  - ext4: fix races between page faults and hole punching
    (bsc#972174).

  - ext4: fix races of writeback with punch hole and zero
    range (bsc#972174).

  - ext4: move unlocked dio protection from
    ext4_alloc_file_blocks() (bsc#972174).

  - ipv4/fib: do not warn when primary address is missing if
    in_dev is dead (bsc#971360).

  - ipvs: count pre-established TCP states as active
    (bsc#970114).

  - net: core: Correct an over-stringent device loop
    detection (bsc#945219).

  - netback: do not use last request to determine minimum Tx
    credit (bsc#957988).

  - pciback: Check PF instead of VF for PCI_COMMAND_MEMORY.

  - pciback: Save the number of MSI-X entries to be copied
    later.

  - pciback: guarantee one time reads of shared ring
    contents (bsc#957988).

  - series.conf: move cxgb3 patch to network drivers section

  - usb: quirk to stop runtime PM for Intel 7260
    (bnc#984464).

  - x86: standardize mmap_rnd() usage (bnc#974308)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=901754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=941113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=942702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=945219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=955654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=959709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=960561"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=961512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=963765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=966849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967973"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967974"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=968670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=969355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970909"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=970970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971124"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=971944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=973570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=974646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=979913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=980725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=981267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=982706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=984764"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986811"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the Linux Kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/25");
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
if (release !~ "^(SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-0.8-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-debugsource-0.8-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-default-debuginfo-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-desktop-debuginfo-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-pae-debuginfo-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"bbswitch-kmp-xen-debuginfo-0.8_k3.16.7_42-3.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-2.639-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debuginfo-2.639-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-debugsource-2.639-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-default-debuginfo-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-desktop-debuginfo-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-pae-debuginfo-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"cloop-kmp-xen-debuginfo-2.639_k3.16.7_42-14.20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debuginfo-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-debugsource-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-devel-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-eppic-debuginfo-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-gcore-debuginfo-7.0.8-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-default-debuginfo-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-desktop-debuginfo-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-pae-debuginfo-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"crash-kmp-xen-debuginfo-7.0.8_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-debugsource-1.28-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-default-debuginfo-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-desktop-debuginfo-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-pae-debuginfo-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"hdjmod-kmp-xen-debuginfo-1.28_k3.16.7_42-18.21.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-6.23-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debuginfo-6.23-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-debugsource-6.23-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-devel-6.23-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-default-debuginfo-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-desktop-debuginfo-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-pae-debuginfo-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"ipset-kmp-xen-debuginfo-6.23_k3.16.7_42-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-default-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-ec2-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-macros-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-3.16.7-42.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-build-debugsource-3.16.7-42.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-obs-qa-xen-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-source-vanilla-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"kernel-syms-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-6.23-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"libipset3-debuginfo-6.23-20.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-0.44-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debuginfo-0.44-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-debugsource-0.44-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-0.44_k3.16.7_42-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-default-debuginfo-0.44_k3.16.7_42-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-0.44_k3.16.7_42-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-desktop-debuginfo-0.44_k3.16.7_42-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-0.44_k3.16.7_42-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"pcfclock-kmp-pae-debuginfo-0.44_k3.16.7_42-260.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"python-virtualbox-debuginfo-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-debugsource-20140629-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-default-debuginfo-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-desktop-debuginfo-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-pae-debuginfo-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"vhba-kmp-xen-debuginfo-20140629_k3.16.7_42-2.20.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debuginfo-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-debugsource-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-devel-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-desktop-icons-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-default-debuginfo-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-desktop-debuginfo-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-kmp-pae-debuginfo-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-tools-debuginfo-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-guest-x11-debuginfo-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-default-debuginfo-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-desktop-debuginfo-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-kmp-pae-debuginfo-5.0.20_k3.16.7_42-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-host-source-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-qt-debuginfo-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"virtualbox-websrv-debuginfo-5.0.20-48.5") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-debugsource-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-devel-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-libs-debuginfo-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xen-tools-domU-debuginfo-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-2.6-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debuginfo-2.6-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-debugsource-2.6-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-default-debuginfo-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-desktop-debuginfo-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-pae-debuginfo-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xtables-addons-kmp-xen-debuginfo-2.6_k3.16.7_42-22.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-desktop-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-pae-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-vanilla-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"i686", reference:"kernel-xen-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-pae-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"kernel-xen-devel-3.16.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-doc-html-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-4.4.4_02_k3.16.7_42-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-default-debuginfo-4.4.4_02_k3.16.7_42-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-4.4.4_02_k3.16.7_42-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-kmp-desktop-debuginfo-4.4.4_02_k3.16.7_42-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-32bit-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-4.4.4_02-46.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.4.4_02-46.2") ) flag++;

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
