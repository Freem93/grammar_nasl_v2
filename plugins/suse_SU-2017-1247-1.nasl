#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1247-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(100150);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/12 13:30:58 $");

  script_cve_id("CVE-2015-1350", "CVE-2016-10044", "CVE-2016-10200", "CVE-2016-10208", "CVE-2016-2117", "CVE-2016-3070", "CVE-2016-5243", "CVE-2016-7117", "CVE-2016-9588", "CVE-2017-2671", "CVE-2017-5669", "CVE-2017-5897", "CVE-2017-5970", "CVE-2017-5986", "CVE-2017-6074", "CVE-2017-6214", "CVE-2017-6345", "CVE-2017-6346", "CVE-2017-6348", "CVE-2017-6353", "CVE-2017-7187", "CVE-2017-7261", "CVE-2017-7294", "CVE-2017-7308", "CVE-2017-7616");
  script_osvdb_id(117818, 135961, 138215, 139499, 145048, 147763, 148861, 151554, 151568, 151927, 152094, 152302, 152453, 152521, 152685, 152705, 152709, 152728, 152729, 153065, 154043, 154359, 154384, 154548, 154633, 155190);

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2017:1247-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 GA LTSS kernel was updated to receive
various security and bugfixes. The following security bugs were 
fixed :

  - CVE-2015-1350: The VFS subsystem in the Linux kernel
    provided an incomplete set of requirements for setattr
    operations that underspecifies removing extended
    privilege attributes, which allowed local users to cause
    a denial of service (capability stripping) via a failed
    invocation of a system call, as demonstrated by using
    chown to remove a capability from the ping or Wireshark
    dumpcap program (bnc#914939).

  - CVE-2016-2117: The atl2_probe function in
    drivers/net/ethernet/atheros/atlx/atl2.c in the Linux
    kernel incorrectly enabled scatter/gather I/O, which
    allowed remote attackers to obtain sensitive information
    from kernel memory by reading packet data (bnc#968697).

  - CVE-2016-3070: The trace_writeback_dirty_page
    implementation in include/trace/events/writeback.h in
    the Linux kernel improperly interacted with
    mm/migrate.c, which allowed local users to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact by
    triggering a certain page move (bnc#979215).

  - CVE-2016-5243: The tipc_nl_compat_link_dump function in
    net/tipc/netlink_compat.c in the Linux kernel did not
    properly copy a certain string, which allowed local
    users to obtain sensitive information from kernel stack
    memory by reading a Netlink message (bnc#983212).

  - CVE-2016-7117: Use-after-free vulnerability in the
    __sys_recvmmsg function in net/socket.c in the Linux
    kernel allowed remote attackers to execute arbitrary
    code via vectors involving a recvmmsg system call that
    is mishandled during error processing (bnc#1003077).

  - CVE-2016-9588: arch/x86/kvm/vmx.c in the Linux kernel
    mismanages the #BP and #OF exceptions, which allowed
    guest OS users to cause a denial of service (guest OS
    crash) by declining to handle an exception thrown by an
    L2 guest (bnc#1015703).

  - CVE-2016-10044: The aio_mount function in fs/aio.c in
    the Linux kernel did not properly restrict execute
    access, which made it easier for local users to bypass
    intended SELinux W^X policy restrictions, and
    consequently gain privileges, via an io_setup system
    call (bnc#1023992).

  - CVE-2016-10200: Race condition in the L2TPv3 IP
    Encapsulation feature in the Linux kernel allowed local
    users to gain privileges or cause a denial of service
    (use-after-free) by making multiple bind system calls
    without properly ascertaining whether a socket has the
    SOCK_ZAPPED status, related to net/l2tp/l2tp_ip.c and
    net/l2tp/l2tp_ip6.c (bnc#1028415).

  - CVE-2016-10208: The ext4_fill_super function in
    fs/ext4/super.c in the Linux kernel did not properly
    validate meta block groups, which allowed physically
    proximate attackers to cause a denial of service
    (out-of-bounds read and system crash) via a crafted ext4
    image (bnc#1023377).

  - CVE-2017-2671: The ping_unhash function in
    net/ipv4/ping.c in the Linux kernel is too late in
    obtaining a certain lock and consequently cannot ensure
    that disconnect function calls are safe, which allowed
    local users to cause a denial of service (panic) by
    leveraging access to the protocol value of IPPROTO_ICMP
    in a socket system call (bnc#1031003).

  - CVE-2017-5669: The do_shmat function in ipc/shm.c in the
    Linux kernel did not restrict the address calculated by
    a certain rounding operation, which allowed local users
    to map page zero, and consequently bypass a protection
    mechanism that exists for the mmap system call, by
    making crafted shmget and shmat system calls in a
    privileged context (bnc#1026914).

  - CVE-2017-5897: The ip6gre_err function in
    net/ipv6/ip6_gre.c in the Linux kernel allowed remote
    attackers to have unspecified impact via vectors
    involving GRE flags in an IPv6 packet, which trigger an
    out-of-bounds access (bnc#1023762).

  - CVE-2017-5970: The ipv4_pktinfo_prepare function in
    net/ipv4/ip_sockglue.c in the Linux kernel allowed
    attackers to cause a denial of service (system crash)
    via (1) an application that made crafted system calls or
    possibly (2) IPv4 traffic with invalid IP options
    (bnc#1024938).

  - CVE-2017-5986: Race condition in the
    sctp_wait_for_sndbuf function in net/sctp/socket.c in
    the Linux kernel allowed local users to cause a denial
    of service (assertion failure and panic) via a
    multithreaded application that peels off an association
    in a certain buffer-full state (bnc#1025235).

  - CVE-2017-6074: The dccp_rcv_state_process function in
    net/dccp/input.c in the Linux kernel mishandled
    DCCP_PKT_REQUEST packet data structures in the LISTEN
    state, which allowed local users to obtain root
    privileges or cause a denial of service (double free)
    via an application that made an IPV6_RECVPKTINFO
    setsockopt system call (bnc#1026024).

  - CVE-2017-6214: The tcp_splice_read function in
    net/ipv4/tcp.c in the Linux kernel allowed remote
    attackers to cause a denial of service (infinite loop
    and soft lockup) via vectors involving a TCP packet with
    the URG flag (bnc#1026722).

  - CVE-2017-6345: The LLC subsystem in the Linux kernel did
    not ensure that a certain destructor exists in required
    circumstances, which allowed local users to cause a
    denial of service (BUG_ON) or possibly have unspecified
    other impact via crafted system calls (bnc#1027190).

  - CVE-2017-6346: Race condition in net/packet/af_packet.c
    in the Linux kernel allowed local users to cause a
    denial of service (use-after-free) or possibly have
    unspecified other impact via a multithreaded application
    that made PACKET_FANOUT setsockopt system calls
    (bnc#1027189).

  - CVE-2017-6348: The hashbin_delete function in
    net/irda/irqueue.c in the Linux kernel improperly
    managed lock dropping, which allowed local users to
    cause a denial of service (deadlock) via crafted
    operations on IrDA devices (bnc#1027178).

  - CVE-2017-6353: net/sctp/socket.c in the Linux kernel did
    not properly restrict association peel-off operations
    during certain wait states, which allowed local users to
    cause a denial of service (invalid unlock and double
    free) via a multithreaded application. NOTE: this
    vulnerability exists because of an incorrect fix for
    CVE-2017-5986 (bnc#1027066).

  - CVE-2017-7187: The sg_ioctl function in
    drivers/scsi/sg.c in the Linux kernel allowed local
    users to cause a denial of service (stack-based buffer
    overflow) or possibly have unspecified other impact via
    a large command size in an SG_NEXT_CMD_LEN ioctl call,
    leading to out-of-bounds write access in the sg_write
    function (bnc#1030213).

  - CVE-2017-7261: The vmw_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel did not check for a zero value of certain levels
    data, which allowed local users to cause a denial of
    service (ZERO_SIZE_PTR dereference, and GPF and possibly
    panic) via a crafted ioctl call for a /dev/dri/renderD*
    device (bnc#1031052).

  - CVE-2017-7294: The vmw_surface_define_ioctl function in
    drivers/gpu/drm/vmwgfx/vmwgfx_surface.c in the Linux
    kernel did not validate addition of certain levels data,
    which allowed local users to trigger an integer overflow
    and out-of-bounds write, and cause a denial of service
    (system hang or crash) or possibly gain privileges, via
    a crafted ioctl call for a /dev/dri/renderD* device
    (bnc#1031440).

  - CVE-2017-7308: The packet_set_ring function in
    net/packet/af_packet.c in the Linux kernel did not
    properly validate certain block-size data, which allowed
    local users to cause a denial of service (overflow) or
    possibly have unspecified other impact via crafted
    system calls (bnc#1031579).

  - CVE-2017-7616: Incorrect error handling in the
    set_mempolicy and mbind compat syscalls in
    mm/mempolicy.c in the Linux kernel allowed local users
    to obtain sensitive information from uninitialized stack
    data by triggering failure of a certain bitmap operation
    (bnc#1033336). The following non-security bugs were
    fixed :

  - ext4: fix fencepost in s_first_meta_bg validation
    (bsc#1029986).

  - hwrng: virtio - ensure reads happen after successful
    probe (bsc#954763 bsc#1032344).

  - kgr/module: make a taint flag module-specific
    (fate#313296).

  - l2tp: fix address test in __l2tp_ip6_bind_lookup()
    (bsc#1028415).

  - l2tp: fix lookup for sockets not bound to a device in
    l2tp_ip (bsc#1028415).

  - l2tp: fix racy socket lookup in l2tp_ip and l2tp_ip6
    bind() (bsc#1028415).

  - l2tp: hold socket before dropping lock in l2tp_ip{,
    6}_recv() (bsc#1028415).

  - l2tp: hold tunnel socket when handling control frames in
    l2tp_ip and l2tp_ip6 (bsc#1028415).

  - l2tp: lock socket before checking flags in connect()
    (bsc#1028415).

  - mm/huge_memory.c: respect FOLL_FORCE/FOLL_COW for thp
    (bnc#1030118).

  - module: move add_taint_module() to a header file
    (fate#313296).

  - netfilter: bridge: Fix the build when IPV6 is disabled
    (bsc#1027149).

  - nfs: flush out dirty data on file fput() (bsc#1021762).

  - powerpc: Blacklist GCC 5.4 6.1 and 6.2 (boo#1028895).

  - powerpc: Reject binutils 2.24 when building little
    endian (boo#1028895).

  - revert 'procfs: mark thread stack correctly in
    proc/<pid>/maps' (bnc#1030901).

  - taint/module: Clean up global and module taint flags
    handling (fate#313296).

  - usb: serial: kl5kusb105: fix line-state error handling
    (bsc#1021256).

  - xfs_dmapi: fix the debug compilation of xfs_dmapi
    (bsc#989056).

  - xfs: fix buffer overflow
    dm_get_dirattrs/dm_get_dirattrs2 (bsc#989056).</pid>

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1003077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1015703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1021762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1023992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1024938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1025235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1026914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027149"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027189"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1027190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028415"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1028895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1029986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1030901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1031579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1032344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1033336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914939"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954763"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979215"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/983212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1350.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10044.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-10208.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-7117.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-2671.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5897.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5986.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6345.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6348.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-6353.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7261.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7294.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7308.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7616.html"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171247-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?673dbaf2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-749=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-749=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2017-749=1

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_72-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-3_12_61-52_72-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_72-default-1-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kgraft-patch-3_12_61-52_72-xen-1-2.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.61-52.72.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.61-52.72.1")) flag++;


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
