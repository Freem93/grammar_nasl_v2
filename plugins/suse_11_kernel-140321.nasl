# @DEPRECATED@
#
# This script has been deprecated as the associated patch is
# no longer available.
#
# Disabled on 2014/06/13.
#

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
  script_id(73244);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/13 11:09:23 $");

  script_cve_id("CVE-2013-4470", "CVE-2013-6885", "CVE-2013-7263", "CVE-2013-7264", "CVE-2013-7265", "CVE-2014-0069");

  script_name(english:"SuSE 11.3 Security Update : Linux Kernel (SAT Patch Numbers 9047 / 9050 / 9051)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to fix
various bugs and security issues.

----------------------------------------------------------------------
- WARNING: If you are running KVM with PCI pass-through on a system
with one of the following Intel chipsets: 5500 (revision 0x13), 5520
(revision 0x13) or X58 (revisions 0x12, 0x13, 0x22), please make sure
to read the following support document before installing this update:
https://www.suse.com/support/kb/doc.php?id=7014344 . You will have to
update your KVM setup to no longer make use of PCI pass-through before
rebooting to the updated kernel.
----------------------------------------------------------------------
-

The following security bugs were fixed :

  - The Linux kernel before 3.12, when UDP Fragmentation
    Offload (UFO) is enabled, does not properly initialize
    certain data structures, which allows local users to
    cause a denial of service (memory corruption and system
    crash) or possibly gain privileges via a crafted
    application that uses the UDP_CORK option in a
    setsockopt system call and sends both short and long
    packets, related to the ip_ufo_append_data function in
    net/ipv4/ip_output.c and the ip6_ufo_append_data
    function in net/ipv6/ip6_output.c. (bnc#847672).
    (CVE-2013-4470)

  - The microcode on AMD 16h 00h through 0Fh processors does
    not properly handle the interaction between locked
    instructions and write-combined memory types, which
    allows local users to cause a denial of service (system
    hang) via a crafted application, aka the errata 793
    issue. (bnc#852967). (CVE-2013-6885)

  - The Linux kernel before 3.12.4 updates certain length
    values before ensuring that associated data structures
    have been initialized, which allows local users to
    obtain sensitive information from kernel stack memory
    via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system
    call, related to net/ipv4/ping.c, net/ipv4/raw.c,
    net/ipv4/udp.c, net/ipv6/raw.c, and net/ipv6/udp.c.
    (bnc#857643). (CVE-2013-7263)

  - The l2tp_ip_recvmsg function in net/l2tp/l2tp_ip.c in
    the Linux kernel before 3.12.4 updates a certain length
    value before ensuring that an associated data structure
    has been initialized, which allows local users to obtain
    sensitive information from kernel stack memory via a (1)
    recvfrom, (2) recvmmsg, or (3) recvmsg system call.
    (bnc#857643). (CVE-2013-7264)

  - The pn_recvmsg function in net/phonet/datagram.c in the
    Linux kernel before 3.12.4 updates a certain length
    value before ensuring that an associated data structure
    has been initialized, which allows local users to obtain
    sensitive information from kernel stack memory via a (1)
    recvfrom, (2) recvmmsg, or (3) recvmsg system call.
    (bnc#857643). (CVE-2013-7265)

  - The cifs_iovec_write function in fs/cifs/file.c in the
    Linux kernel through 3.13.5 does not properly handle
    uncached write operations that copy fewer than the
    requested number of bytes, which allows local users to
    obtain sensitive information from kernel memory, cause a
    denial of service (memory corruption and system crash),
    or possibly gain privileges via a writev system call
    with a crafted pointer. (bnc#864025). (CVE-2014-0069)

The following non-security bugs were fixed :

  - kabi: protect symbols modified by bnc#864833 fix.
    (bnc#864833)

  - mm: mempolicy: fix mbind_range() &amp;&amp; vma_adjust()
    interaction (VM Functionality (bnc#866428)).

  - mm: merging memory blocks resets mempolicy (VM
    Functionality (bnc#866428)).

  - mm/page-writeback.c: do not count anon pages as
    dirtyable memory (High memory utilisation performance
    (bnc#859225)).

  - mm: vmscan: Do not force reclaim file pages until it
    exceeds anon (High memory utilisation performance
    (bnc#859225)).

  - mm: vmscan: fix endless loop in kswapd balancing (High
    memory utilisation performance (bnc#859225)).

  - mm: vmscan: Update rotated and scanned when force
    reclaimed (High memory utilisation performance
    (bnc#859225)).

  - mm: exclude memory less nodes from zone_reclaim.
    (bnc#863526)

  - mm: fix return type for functions nr_free_*_pages kabi
    fixup. (bnc#864058)

  - mm: fix return type for functions nr_free_*_pages.
    (bnc#864058)

  - mm: swap: Use swapfiles in priority order (Use swap
    files in priority order (bnc#862957)).

  - x86: Save cr2 in NMI in case NMIs take a page fault
    (follow-up for
    patches.fixes/x86-Add-workaround-to-NMI-iret-woes.patch)
    .

  - powerpc: Add VDSO version of getcpu (fate#316816,
    bnc#854445).

  - vmscan: change type of vm_total_pages to unsigned long.
    (bnc#864058)

  - audit: dynamically allocate audit_names when not enough
    space is in the names array. (bnc#857358)

  - audit: make filetype matching consistent with other
    filters. (bnc#857358)

  - arch/x86/mm/srat: Skip NUMA_NO_NODE while parsing SLIT.
    (bnc#863178)

  - hwmon: (coretemp) Fix truncated name of alarm
    attributes.

  - privcmd: allow preempting long running user-mode
    originating hypercalls. (bnc#861093)

  - nohz: Check for nohz active instead of nohz enabled.
    (bnc#846790)

  - nohz: Fix another inconsistency between CONFIG_NO_HZ=n
    and nohz=off. (bnc#846790)

  - iommu/vt-d: add quirk for broken interrupt remapping on
    55XX chipsets. (bnc#844513)

  - balloon: do not crash in HVM-with-PoD guests.

  - crypto: s390 - fix des and des3_ede ctr concurrency
    issue (bnc#862796, LTC#103744).

  - crypto: s390 - fix des and des3_ede cbc concurrency
    issue (bnc#862796, LTC#103743).

  - kernel: oops due to linkage stack instructions
    (bnc#862796, LTC#103860).

  - crypto: s390 - fix concurrency issue in aes-ctr mode
    (bnc#862796, LTC#103742).

  - dump: Fix dump memory detection (bnc#862796,LTC#103575).

  - net: change type of virtio_chan->p9_max_pages.
    (bnc#864058)

  - inet: Avoid potential NULL peer dereference.
    (bnc#864833)

  - inet: Hide route peer accesses behind helpers.
    (bnc#864833)

  - inet: Pass inetpeer root into inet_getpeer*()
    interfaces. (bnc#864833)

  - tcp: syncookies: reduce cookie lifetime to 128 seconds.
    (bnc#833968)

  - tcp: syncookies: reduce mss table to four values.
    (bnc#833968)

  - ipv6 routing, NLM_F_* flag support: REPLACE and EXCL
    flags support, warn about missing CREATE flag.
    (bnc#865783)

  - ipv6: send router reachability probe if route has an
    unreachable gateway. (bnc#853162)

  - sctp: Implement quick failover draft from tsvwg.
    (bnc#827670)

  - ipvs: fix AF assignment in ip_vs_conn_new().
    (bnc#856848)

  - NFSD/sunrpc: avoid deadlock on TCP connection due to
    memory pressure. (bnc#853455)

  - btrfs: bugfix collection

  - fs/nfsd: change type of max_delegations,
    nfsd_drc_max_mem and nfsd_drc_mem_used. (bnc#864058)

  - fs/buffer.c: change type of max_buffer_heads to unsigned
    long. (bnc#864058)

  - ncpfs: fix rmdir returns Device or resource busy.
    (bnc#864880)

  - fs/fscache: Handle removal of unadded object to the
    fscache_object_list rb tree. (bnc#855885)

  - scsi_dh_alua: fixup RTPG retry delay miscalculation.
    (bnc#854025)

  - scsi_dh_alua: Simplify state machine. (bnc#854025)

  - xhci: Fix resume issues on Renesas chips in Samsung
    laptops. (bnc#866253)

  - bonding: disallow enslaving a bond to itself.
    (bnc#599263)

  - USB: hub: handle -ETIMEDOUT during enumeration.
    (bnc#855825)

  - dm-multipath: Do not stall on invalid ioctls.
    (bnc#865342)

  - scsi_dh_alua: endless STPG retries for a failed LUN.
    (bnc#865342)

  - net/mlx4_en: Fix pages never dma unmapped on rx.
    (bnc#858604)

  - dlm: remove get_comm. (bnc#827670)

  - dlm: Avoid LVB truncation. (bnc#827670)

  - dlm: disable nagle for SCTP. (bnc#827670)

  - dlm: retry failed SCTP sends. (bnc#827670)

  - dlm: try other IPs when sctp init assoc fails.
    (bnc#827670)

  - dlm: clear correct bit during sctp init failure
    handling. (bnc#827670)

  - dlm: set sctp assoc id during setup. (bnc#827670)

  - dlm: clear correct init bit during sctp setup.
    (bnc#827670)

  - dlm: fix deadlock between dlm_send and dlm_controld.
    (bnc#827670)

  - dlm: Fix return value from lockspace_busy().
    (bnc#827670)

  - Avoid occasional hang with NFS. (bnc#852488)

  - mpt2sas: Fix unsafe using smp_processor_id() in
    preemptible. (bnc#853166)

  - lockd: send correct lock when granting a delayed lock.
    (bnc#859342)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=599263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=827670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=847672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852488"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=855825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=855885"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=857643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=861093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862957"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=863526"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=866428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6885.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7263.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7264.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-7265.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0069.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 9047 / 9050 / 9051 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}

# Deprecated.
exit(0, "The associated patch is no longer available.");



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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-default-extra-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-source-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-syms-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.18-0.7.5")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_02_3.0.101_0.18-0.7.5")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-source-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-syms-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.18-0.7.5")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-default-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-source-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-syms-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"kernel-trace-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.18-0.7.5")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"i586", reference:"xen-kmp-pae-4.2.4_02_3.0.101_0.18-0.7.5")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"kernel-default-man-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"xen-kmp-default-4.2.4_02_3.0.101_0.18-0.7.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
