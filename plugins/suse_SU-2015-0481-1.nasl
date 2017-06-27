#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0481-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83696);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2010-5313", "CVE-2012-4398", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-2899", "CVE-2013-2929", "CVE-2013-7263", "CVE-2014-0131", "CVE-2014-0181", "CVE-2014-2309", "CVE-2014-3181", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3646", "CVE-2014-3647", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-3690", "CVE-2014-4608", "CVE-2014-4943", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-7826", "CVE-2014-7841", "CVE-2014-7842", "CVE-2014-8134", "CVE-2014-8369", "CVE-2014-8559", "CVE-2014-8709", "CVE-2014-9584", "CVE-2014-9585");
  script_bugtraq_id(55361, 62044, 62046, 62050, 64111, 64686, 66095, 66101, 67034, 68214, 68683, 68768, 69396, 69428, 69489, 69763, 69768, 69779, 69781, 70691, 70742, 70745, 70747, 70748, 70749, 70766, 70768, 70854, 70883, 70965, 70971, 71078, 71081, 71363, 71650, 71883, 71990);
  script_osvdb_id(85718, 96768, 96770, 96774, 100422, 106174, 108489, 109277, 110240, 110564, 110565, 110567, 110568, 110569, 110570, 110571, 110572, 110732, 111406, 111409, 113629, 113724, 113726, 113727, 113728, 113731, 113823, 113899, 114044, 114370, 114393, 114575, 114689, 115870, 116767, 116910);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2015:0481-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 2 LTSS kernel has been
updated to fix security issues on kernels on the x86_64 architecture.

The following security bugs have been fixed :

  - CVE-2012-4398: The __request_module function in
    kernel/kmod.c in the Linux kernel before 3.4 did not set
    a certain killable attribute, which allowed local users
    to cause a denial of service (memory consumption) via a
    crafted application (bnc#779488).

  - CVE-2013-2893: The Human Interface Device (HID)
    subsystem in the Linux kernel through 3.11, when
    CONFIG_LOGITECH_FF, CONFIG_LOGIG940_FF, or
    CONFIG_LOGIWHEELS_FF is enabled, allowed physically
    proximate attackers to cause a denial of service
    (heap-based out-of-bounds write) via a crafted device,
    related to (1) drivers/hid/hid-lgff.c, (2)
    drivers/hid/hid-lg3ff.c, and (3) drivers/hid/hid-lg4ff.c
    (bnc#835839).

  - CVE-2013-2897: Multiple array index errors in
    drivers/hid/hid-multitouch.c in the Human Interface
    Device (HID) subsystem in the Linux kernel through 3.11,
    when CONFIG_HID_MULTITOUCH is enabled, allowed
    physically proximate attackers to cause a denial of
    service (heap memory corruption, or NULL pointer
    dereference and OOPS) via a crafted device (bnc#835839).

  - CVE-2013-2899: drivers/hid/hid-picolcd_core.c in the
    Human Interface Device (HID) subsystem in the Linux
    kernel through 3.11, when CONFIG_HID_PICOLCD is enabled,
    allowed physically proximate attackers to cause a denial
    of service (NULL pointer dereference and OOPS) via a
    crafted device (bnc#835839).

  - CVE-2013-2929: The Linux kernel before 3.12.2 did not
    properly use the get_dumpable function, which allowed
    local users to bypass intended ptrace restrictions or
    obtain sensitive information from IA64 scratch registers
    via a crafted application, related to kernel/ptrace.c
    and arch/ia64/include/asm/processor.h (bnc#847652).

  - CVE-2013-7263: The Linux kernel before 3.12.4 updates
    certain length values before ensuring that associated
    data structures have been initialized, which allowed
    local users to obtain sensitive information from kernel
    stack memory via a (1) recvfrom, (2) recvmmsg, or (3)
    recvmsg system call, related to net/ipv4/ping.c,
    net/ipv4/raw.c, net/ipv4/udp.c, net/ipv6/raw.c, and
    net/ipv6/udp.c (bnc#857643).

  - CVE-2014-0131: Use-after-free vulnerability in the
    skb_segment function in net/core/skbuff.c in the Linux
    kernel through 3.13.6 allowed attackers to obtain
    sensitive information from kernel memory by leveraging
    the absence of a certain orphaning operation
    (bnc#867723).

  - CVE-2014-0181: The Netlink implementation in the Linux
    kernel through 3.14.1 did not provide a mechanism for
    authorizing socket operations based on the opener of a
    socket, which allowed local users to bypass intended
    access restrictions and modify network configurations by
    using a Netlink socket for the (1) stdout or (2) stderr
    of a setuid program (bnc#875051).

  - CVE-2014-2309: The ip6_route_add function in
    net/ipv6/route.c in the Linux kernel through 3.13.6 did
    not properly count the addition of routes, which allowed
    remote attackers to cause a denial of service (memory
    consumption) via a flood of ICMPv6 Router Advertisement
    packets (bnc#867531).

  - CVE-2014-3181: Multiple stack-based buffer overflows in
    the magicmouse_raw_event function in
    drivers/hid/hid-magicmouse.c in the Magic Mouse HID
    driver in the Linux kernel through 3.16.3 allowed
    physically proximate attackers to cause a denial of
    service (system crash) or possibly execute arbitrary
    code via a crafted device that provides a large amount
    of (1) EHCI or (2) XHCI data associated with an event
    (bnc#896382).

  - CVE-2014-3184: The report_fixup functions in the HID
    subsystem in the Linux kernel before 3.16.2 might have
    allowed physically proximate attackers to cause a denial
    of service (out-of-bounds write) via a crafted device
    that provides a small report descriptor, related to (1)
    drivers/hid/hid-cherry.c, (2) drivers/hid/hid-kye.c, (3)
    drivers/hid/hid-lg.c, (4) drivers/hid/hid-monterey.c,
    (5) drivers/hid/hid-petalynx.c, and (6)
    drivers/hid/hid-sunplus.c (bnc#896390).

  - CVE-2014-3185: Multiple buffer overflows in the
    command_port_read_callback function in
    drivers/usb/serial/whiteheat.c in the Whiteheat USB
    Serial Driver in the Linux kernel before 3.16.2 allowed
    physically proximate attackers to execute arbitrary code
    or cause a denial of service (memory corruption and
    system crash) via a crafted device that provides a large
    amount of (1) EHCI or (2) XHCI data associated with a
    bulk response (bnc#896391).

  - CVE-2014-3186: Buffer overflow in the picolcd_raw_event
    function in devices/hid/hid-picolcd_core.c in the
    PicoLCD HID device driver in the Linux kernel through
    3.16.3, as used in Android on Nexus 7 devices, allowed
    physically proximate attackers to cause a denial of
    service (system crash) or possibly execute arbitrary
    code via a crafted device that sends a large report
    (bnc#896392).

  - CVE-2014-3601: The kvm_iommu_map_pages function in
    virt/kvm/iommu.c in the Linux kernel through 3.16.1
    miscalculates the number of pages during the handling of
    a mapping failure, which allowed guest OS users to (1)
    cause a denial of service (host OS memory corruption) or
    possibly have unspecified other impact by triggering a
    large gfn value or (2) cause a denial of service (host
    OS memory consumption) by triggering a small gfn value
    that leads to permanently pinned pages (bnc#892782).

  - CVE-2014-3610: The WRMSR processing functionality in the
    KVM subsystem in the Linux kernel through 3.17.2 did not
    properly handle the writing of a non-canonical address
    to a model-specific register, which allowed guest OS
    users to cause a denial of service (host OS crash) by
    leveraging guest OS privileges, related to the
    wrmsr_interception function in arch/x86/kvm/svm.c and
    the handle_wrmsr function in arch/x86/kvm/vmx.c
    (bnc#899192).

  - CVE-2014-3646: arch/x86/kvm/vmx.c in the KVM subsystem
    in the Linux kernel through 3.17.2 did not have an exit
    handler for the INVVPID instruction, which allowed guest
    OS users to cause a denial of service (guest OS crash)
    via a crafted application (bnc#899192).

  - CVE-2014-3647: arch/x86/kvm/emulate.c in the KVM
    subsystem in the Linux kernel through 3.17.2 did not
    properly perform RIP changes, which allowed guest OS
    users to cause a denial of service (guest OS crash) via
    a crafted application (bnc#899192).

  - CVE-2014-3673: The SCTP implementation in the Linux
    kernel through 3.17.2 allowed remote attackers to cause
    a denial of service (system crash) via a malformed
    ASCONF chunk, related to net/sctp/sm_make_chunk.c and
    net/sctp/sm_statefuns.c (bnc#902346).

  - CVE-2014-3687: The sctp_assoc_lookup_asconf_ack function
    in net/sctp/associola.c in the SCTP implementation in
    the Linux kernel through 3.17.2 allowed remote attackers
    to cause a denial of service (panic) via duplicate
    ASCONF chunks that trigger an incorrect uncork within
    the side-effect interpreter (bnc#902349).

  - CVE-2014-3688: The SCTP implementation in the Linux
    kernel before 3.17.4 allowed remote attackers to cause a
    denial of service (memory consumption) by triggering a
    large number of chunks in an associations output queue,
    as demonstrated by ASCONF probes, related to
    net/sctp/inqueue.c and net/sctp/sm_statefuns.c
    (bnc#902351).

  - CVE-2014-3690: arch/x86/kvm/vmx.c in the KVM subsystem
    in the Linux kernel before 3.17.2 on Intel processors
    did not ensure that the value in the CR4 control
    register remains the same after a VM entry, which
    allowed host OS users to kill arbitrary processes or
    cause a denial of service (system disruption) by
    leveraging /dev/kvm access, as demonstrated by
    PR_SET_TSC prctl calls within a modified copy of QEMU
    (bnc#902232).

  - CVE-2014-4608: Multiple integer overflows in the
    lzo1x_decompress_safe function in
    lib/lzo/lzo1x_decompress_safe.c in the LZO decompressor
    in the Linux kernel before 3.15.2 allowed
    context-dependent attackers to cause a denial of service
    (memory corruption) via a crafted Literal Run
    (bnc#883948).

  - CVE-2014-4943: The PPPoL2TP feature in
    net/l2tp/l2tp_ppp.c in the Linux kernel through 3.15.6
    allowed local users to gain privileges by leveraging
    data-structure differences between an l2tp socket and an
    inet socket (bnc#887082).

  - CVE-2014-5471: Stack consumption vulnerability in the
    parse_rock_ridge_inode_internal function in
    fs/isofs/rock.c in the Linux kernel through 3.16.1
    allowed local users to cause a denial of service
    (uncontrolled recursion, and system crash or reboot) via
    a crafted iso9660 image with a CL entry referring to a
    directory entry that has a CL entry (bnc#892490).

  - CVE-2014-5472: The parse_rock_ridge_inode_internal
    function in fs/isofs/rock.c in the Linux kernel through
    3.16.1 allowed local users to cause a denial of service
    (unkillable mount process) via a crafted iso9660 image
    with a self-referential CL entry (bnc#892490).

  - CVE-2014-7826: kernel/trace/trace_syscalls.c in the
    Linux kernel through 3.17.2 did not properly handle
    private syscall numbers during use of the ftrace
    subsystem, which allowed local users to gain privileges
    or cause a denial of service (invalid pointer
    dereference) via a crafted application (bnc#904013).

  - CVE-2014-7841: The sctp_process_param function in
    net/sctp/sm_make_chunk.c in the SCTP implementation in
    the Linux kernel before 3.17.4, when ASCONF is used,
    allowed remote attackers to cause a denial of service
    (NULL pointer dereference and system crash) via a
    malformed INIT chunk (bnc#905100).

  - CVE-2014-7842: Race condition in arch/x86/kvm/x86.c in
    the Linux kernel before 3.17.4 allowed guest OS users to
    cause a denial of service (guest OS crash) via a crafted
    application that performs an MMIO transaction or a PIO
    transaction to trigger a guest userspace emulation error
    report, a similar issue to CVE-2010-5313 (bnc#905312).

  - CVE-2014-8134: The paravirt_ops_setup function in
    arch/x86/kernel/kvm.c in the Linux kernel through 3.18
    uses an improper paravirt_enabled setting for KVM guest
    kernels, which made it easier for guest OS users to
    bypass the ASLR protection mechanism via a crafted
    application that reads a 16-bit value (bnc#909078).

  - CVE-2014-8369: The kvm_iommu_map_pages function in
    virt/kvm/iommu.c in the Linux kernel through 3.17.2
    miscalculates the number of pages during the handling of
    a mapping failure, which allowed guest OS users to cause
    a denial of service (host OS page unpinning) or possibly
    have unspecified other impact by leveraging guest OS
    privileges. NOTE: this vulnerability exists because of
    an incorrect fix for CVE-2014-3601 (bnc#902675).

  - CVE-2014-8559: The d_walk function in fs/dcache.c in the
    Linux kernel through 3.17.2 did not properly maintain
    the semantics of rename_lock, which allowed local users
    to cause a denial of service (deadlock and system hang)
    via a crafted application (bnc#903640).

  - CVE-2014-8709: The ieee80211_fragment function in
    net/mac80211/tx.c in the Linux kernel before 3.13.5 did
    not properly maintain a certain tail pointer, which
    allowed remote attackers to obtain sensitive cleartext
    information by reading packets (bnc#904700).

  - CVE-2014-9584: The parse_rock_ridge_inode_internal
    function in fs/isofs/rock.c in the Linux kernel before
    3.18.2 did not validate a length value in the Extensions
    Reference (ER) System Use Field, which allowed local
    users to obtain sensitive information from kernel memory
    via a crafted iso9660 image (bnc#912654).

  - CVE-2014-9585: The vdso_addr function in
    arch/x86/vdso/vma.c in the Linux kernel through 3.18.2
    did not properly choose memory locations for the vDSO
    area, which made it easier for local users to bypass the
    ASLR protection mechanism by guessing a location at the
    end of a PMD (bnc#912705).

The following non-security bugs have been fixed :

  - Fix HDIO_DRIVE_* ioctl() Linux 3.9 regression
    (bnc#833588, bnc#905799).

  - HID: add usage_index in struct hid_usage (bnc#835839).

  - Revert PM / reboot: call syscore_shutdown() after
    disable_nonboot_cpus() Reduce time to shutdown large
    machines (bnc#865442 bnc#907396).

  - Revert kernel/sys.c: call disable_nonboot_cpus() in
    kernel_restart() Reduce time to shutdown large machines
    (bnc#865442 bnc#907396).

  - dm-mpath: fix panic on deleting sg device (bnc#870161).

  - futex: Unlock hb->lock in futex_wait_requeue_pi() error
    path (fix bnc#880892).

  - handle more than just WS2008 in heartbeat negotiation
    (bnc#901885).

  - memcg: do not expose uninitialized mem_cgroup_per_node
    to world (bnc#883096).

  - mm: fix BUG in __split_huge_page_pmd (bnc#906586).

  - pagecachelimit: reduce lru_lock congestion for heavy
    parallel reclaim fix (bnc#895680, bnc#907189).

  - s390/3215: fix hanging console issue (bnc#898693,
    bnc#897995, LTC#115466).

  - s390/cio: improve cio_commit_config (bnc#864049,
    bnc#898693, LTC#104168).

  - scsi_dh_alua: disable ALUA handling for non-disk devices
    (bnc#876633).

  - target/rd: Refactor rd_build_device_space +
    rd_release_device_space.

  - timekeeping: Avoid possible deadlock from
    clock_was_set_delayed (bnc#771619, bnc#915335).

  - xfs: recheck buffer pinned status after push trylock
    failure (bnc#907338).

  - xfs: remove log force from xfs_buf_trylock()
    (bnc#907338).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=1aca006b7fb12ba06b40aba057729bf1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?173c46f7"
  );
  # http://download.suse.com/patch/finder/?keywords=276c3f04008f2b450bc62f6bb64d06fc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c34ef91f"
  );
  # http://download.suse.com/patch/finder/?keywords=450d3910ce461844d33188377a397db4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f9e9976"
  );
  # http://download.suse.com/patch/finder/?keywords=55fa96c03a923b1679e1f132d850294c
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06c7c9aa"
  );
  # http://download.suse.com/patch/finder/?keywords=9462f7a25fba741ea356e4bc7df2eff7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06a30d66"
  );
  # http://download.suse.com/patch/finder/?keywords=9d8f78866ba011d27c2f208e892fe2d8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba4206a7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4398.html"
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
    value:"http://support.novell.com/security/cve/CVE-2013-2929.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-2309.html"
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
    value:"http://support.novell.com/security/cve/CVE-2014-3687.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3688.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-3690.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-4943.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-5472.html"
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
    value:"http://support.novell.com/security/cve/CVE-2014-7842.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/771619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/779488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/833588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/835839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/847652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/857643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/864049"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/865442"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/870161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/875051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/876633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/880892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/883096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/883948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/887082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/892490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/892782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/895680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896390"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/897995"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902349"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/903640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/906586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915335"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150481-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?feca593f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 LTSS :

zypper in -t patch slessp2-kernel=10239 slessp2-kernel=10245
slessp2-kernel=10246

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.29-0.5.19")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.29-0.5.19")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"x86_64", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.29-0.5.19")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-default-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-source-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-syms-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"kernel-trace-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-default-4.1.6_08_3.0.101_0.7.29-0.5.19")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-trace-4.1.6_08_3.0.101_0.7.29-0.5.19")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.7.29.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", cpu:"i586", reference:"xen-kmp-pae-4.1.6_08_3.0.101_0.7.29-0.5.19")) flag++;


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
