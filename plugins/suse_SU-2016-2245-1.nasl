#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2245-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93370);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2013-4312", "CVE-2015-7513", "CVE-2015-7833", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-2187", "CVE-2016-3134", "CVE-2016-3955", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5244", "CVE-2016-5696", "CVE-2016-5829", "CVE-2016-6480");
  script_osvdb_id(128557, 132618, 133379, 133550, 135678, 137359, 137841, 137963, 138086, 138093, 138176, 138383, 138431, 138444, 138451, 138785, 139498, 139987, 140046, 140493, 140494, 140558, 141441, 142610);

  script_name(english:"SUSE SLES11 Security Update : kernel (SUSE-SU-2016:2245-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated to receive
various security and bugfixes. The following security bugs were 
fixed :

  - CVE-2016-3955: The usbip_recv_xbuff function in
    drivers/usb/usbip/usbip_common.c in the Linux kernel
    allowed remote attackers to cause a denial of service
    (out-of-bounds write) or possibly have unspecified other
    impact via a crafted length value in a USB/IP packet
    (bnc#975945).

  - CVE-2016-4998: The IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds read) or possibly obtain sensitive
    information from kernel heap memory by leveraging
    in-container root access to provide a crafted offset
    value that leads to crossing a ruleset blob boundary
    (bnc#986365).

  - CVE-2015-7513: arch/x86/kvm/x86.c in the Linux kernel
    did not reset the PIT counter values during state
    restoration, which allowed guest OS users to cause a
    denial of service (divide-by-zero error and host OS
    crash) via a zero value, related to the
    kvm_vm_ioctl_set_pit and kvm_vm_ioctl_set_pit2 functions
    (bnc#960689).

  - CVE-2013-4312: The Linux kernel allowed local users to
    bypass file-descriptor limits and cause a denial of
    service (memory consumption) by sending each descriptor
    over a UNIX socket before closing it, related to
    net/unix/af_unix.c and net/unix/garbage.c (bnc#839104).

  - CVE-2016-4997: The compat IPT_SO_SET_REPLACE setsockopt
    implementation in the netfilter subsystem in the Linux
    kernel allowed local users to gain privileges or cause a
    denial of service (memory corruption) by leveraging
    in-container root access to provide a crafted offset
    value that triggers an unintended decrement
    (bnc#986362).

  - CVE-2016-5829: Multiple heap-based buffer overflows in
    the hiddev_ioctl_usage function in
    drivers/hid/usbhid/hiddev.c in the Linux kernel allow
    local users to cause a denial of service or possibly
    have unspecified other impact via a crafted (1)
    HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call
    (bnc#986572).

  - CVE-2016-4470: The key_reject_and_link function in
    security/keys/key.c in the Linux kernel did not ensure
    that a certain data structure was initialized, which
    allowed local users to cause a denial of service (system
    crash) via vectors involving a crafted keyctl request2
    command (bnc#984755).

  - CVE-2016-5244: The rds_inc_info_copy function in
    net/rds/recv.c in the Linux kernel did not initialize a
    certain structure member, which allowed remote attackers
    to obtain sensitive information from kernel stack memory
    by reading an RDS message (bnc#983213).

  - CVE-2016-1583: The ecryptfs_privileged_open function in
    fs/ecryptfs/kthread.c in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (stack memory consumption) via vectors involving crafted
    mmap calls for /proc pathnames, leading to recursive
    pagefault handling (bnc#983143).

  - CVE-2016-4913: The get_rock_ridge_filename function in
    fs/isofs/rock.c in the Linux kernel mishandled NM (aka
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

  - CVE-2016-4805: Use-after-free vulnerability in
    drivers/net/ppp/ppp_generic.c in the Linux kernel
    allowed local users to cause a denial of service (memory
    corruption and system crash, or spinlock) or possibly
    have unspecified other impact by removing a network
    namespace, related to the ppp_register_net_channel and
    ppp_unregister_channel functions (bnc#980371).

  - CVE-2016-0758: Integer overflow in lib/asn1_decoder.c in
    the Linux kernel allowed local users to gain privileges
    via crafted ASN.1 data (bnc#979867).

  - CVE-2015-7833: The usbvision driver in the Linux kernel
    allowed physically proximate attackers to cause a denial
    of service (panic) via a nonzero bInterfaceNumber value
    in a USB device descriptor (bnc#950998).

  - CVE-2016-2187: The gtco_probe function in
    drivers/input/tablet/gtco.c in the Linux kernel allowed
    physically proximate attackers to cause a denial of
    service (NULL pointer dereference and system crash) via
    a crafted endpoints value in a USB device descriptor
    (bnc#971944).

  - CVE-2016-4482: The proc_connectinfo function in
    drivers/usb/core/devio.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via a crafted USBDEVFS_CONNECTINFO ioctl call
    (bnc#978401).

  - CVE-2016-4565: The InfiniBand (aka IB) stack in the
    Linux kernel incorrectly relies on the write system
    call, which allowed local users to cause a denial of
    service (kernel memory write operation) or possibly have
    unspecified other impact via a uAPI interface
    (bnc#979548).

  - CVE-2016-2053: The asn1_ber_decoder function in
    lib/asn1_decoder.c in the Linux kernel allowed attackers
    to cause a denial of service (panic) via an ASN.1 BER
    file that lacks a public key, leading to mishandling by
    the public_key_verify_signature function in
    crypto/asymmetric_keys/public_key.c (bnc#963762).

  - CVE-2016-4485: The llc_cmsg_rcv function in
    net/llc/af_llc.c in the Linux kernel did not initialize
    a certain data structure, which allowed attackers to
    obtain sensitive information from kernel stack memory by
    reading a message (bnc#978821).

  - CVE-2016-4578: sound/core/timer.c in the Linux kernel
    did not initialize certain r1 data structures, which
    allowed local users to obtain sensitive information from
    kernel stack memory via crafted use of the ALSA timer
    interface, related to the (1) snd_timer_user_ccallback
    and (2) snd_timer_user_tinterrupt functions
    (bnc#979879).

  - CVE-2016-4569: The snd_timer_user_params function in
    sound/core/timer.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory via crafted use of the ALSA timer interface
    (bnc#979213).

  - CVE-2016-4486: The rtnl_fill_link_ifmap function in
    net/core/rtnetlink.c in the Linux kernel did not
    initialize a certain data structure, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#978822).

  - CVE-2016-3134: The netfilter subsystem in the Linux
    kernel did not validate certain offset fields, which
    allowed local users to gain privileges or cause a denial
    of service (heap memory corruption) via an
    IPT_SO_SET_REPLACE setsockopt call (bnc#971126).

  - CVE-2016-5696: net/ipv4/tcp_input.c in the Linux kernel
    did not properly determine the rate of challenge ACK
    segments, which made it easier for man-in-the-middle
    attackers to hijack TCP sessions via a blind in-window
    attack. (bsc#989152)

  - CVE-2016-6480: Race condition in the ioctl_send_fib
    function in drivers/scsi/aacraid/commctrl.c in the Linux
    kernel allowed local users to cause a denial of service
    (out-of-bounds access or system crash) by changing a
    certain size value, aka a 'double fetch' vulnerability.
    (bsc#991608) The following non-security bugs were 
fixed :

  - Update
    patches.fixes/pci-determine-actual-vpd-size-on-first-acc
    ess.patch (bsc#971729, bsc#974428).

  - Update PCI VPD size patch to upstream :

  - PCI: Determine actual VPD size on first access
    (bsc#971729).

  - PCI: Update VPD definitions (bsc#971729). (cherry picked
    from commit d2af5b7e0cd7ee2a54f02ad65ec300d16b3ad956)

  - Update patches.fixes/pci-update-vpd-definitions.patch
    (bsc#971729, bsc#974428).

  - cgroups: do not attach task to subsystem if migration
    failed (bnc#979274).

  - cgroups: more safe tasklist locking in
    cgroup_attach_proc (bnc#979274).

  - fs/cifs: Fix cifs_uniqueid_to_ino_t() function for s390x
    (bsc#944309)

  - fs/cifs: fix wrongly prefixed path to root (bsc#963655,
    bsc#979681)

  - hid: add ALWAYS_POLL quirk for a Logitech 0xc055
    (bnc#962404).

  - hid: add HP OEM mouse to quirk ALWAYS_POLL (bsc#919351).

  - hid: add quirk for PIXART OEM mouse used by HP
    (bsc#919351).

  - hid-elo: kill not flush the work.

  - ipv4/fib: do not warn when primary address is missing if
    in_dev is dead (bsc#971360).

  - ipv4: fix ineffective source address selection
    (bsc#980788).

  - ipvs: count pre-established TCP states as active
    (bsc#970114).

  - kabi, unix: properly account for FDs passed over unix
    sockets (bnc#839104).

  - mm/hugetlb.c: correct missing private flag clearing (VM
    Functionality, bnc#971446).

  - mm/hugetlb: fix backport of upstream commit 07443a85ad
    (VM Functionality, bnc#971446).

  - mm: thp: fix SMP race condition between THP page fault
    and MADV_DONTNEED (VM Functionality, bnc#986445).

  - nfs: Do not attempt to decode missing directory entries
    (bsc#980931).

  - nfs: fix memory corruption rooted in get_ih_name pointer
    math (bsc#984107).

  - nfs: reduce access cache shrinker locking (bnc#866130).

  - ppp: defer netns reference release for ppp channel
    (bsc#980371).

  - s390/cio: collect format 1 channel-path description data
    (bsc#966460,LTC#136434).

  - s390/cio: ensure consistent measurement state
    (bsc#966460,LTC#136434).

  - s390/cio: fix measurement characteristics memleak
    (bsc#966460,LTC#136434).

  - s390/cio: update measurement characteristics
    (bsc#966460,LTC#136434).

  - usbhid: add device USB_DEVICE_ID_LOGITECH_C077
    (bsc#919351).

  - usbhid: more mice with ALWAYS_POLL (bsc#919351).

  - usbhid: yet another mouse with ALWAYS_POLL (bsc#919351).

  - veth: do not modify ip_summed (bsc#969149).

  - virtio_scsi: Implement eh_timed_out callback.

  - vmxnet3: segCnt can be 1 for LRO packets (bsc#988065).

  - xfs: Avoid grabbing ilock when file size is not changed
    (bsc#983535).

  - xfs: avoid xfs_buf hang in lookup node directory
    corruption (bsc#989401).

  - xfs: only update the last_sync_lsn when a transaction
    completes (bsc#987709).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/839104"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/866130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/944309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/950998"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/963762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/966460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/974428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979879"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980725"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/984755"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986365"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/986572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/987709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/988065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/991608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-4312.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4486.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4565.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4580.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4805.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4998.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5244.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5696.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6480.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162245-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?529403fa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-kernel-12730=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-kernel-12730=1

SUSE Manager 2.1:zypper in -t patch sleman21-kernel-12730=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-kernel-12730=1

SUSE Linux Enterprise Server 11-EXTRA:zypper in -t patch
slexsp3-kernel-12730=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-kernel-12730=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-kernel-12730=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/08");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.86.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.86.1")) flag++;


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
