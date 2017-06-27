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
  script_id(64173);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/20 15:05:37 $");

  script_cve_id("CVE-2011-1083", "CVE-2011-4086", "CVE-2011-4622", "CVE-2012-0045", "CVE-2012-0879", "CVE-2012-1090", "CVE-2012-1097", "CVE-2012-2133");

  script_name(english:"SuSE 11.1 Security Update : Linux kernel (SAT Patch Numbers 6227 / 6229 / 6230)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP1 kernel has been updated to the
2.6.32.59 stable release to fix a lot of bugs and security issues.

The following security issues have been fixed :

  - A use after free bug in hugetlb support could be used by
    local attackers to crash the system. (CVE-2012-2133)

  - A NULL pointer dereference bug in the regsets proc file
    could be used by local attackers to perhaps crash the
    system. With mmap_min_addr is set and enabled,
    exploitation is unlikely. (CVE-2012-1097)

  - A reference counting issue in CLONE_IO could be used by
    local attackers to cause a denial of service (out of
    memory). (CVE-2012-0879)

  - A file handle leak in CIFS code could be used by local
    attackers to crash the system. (CVE-2012-1090)

  - Large nested epoll chains could be used by local
    attackers to cause a denial of service (excessive CPU
    consumption). (CVE-2011-1083)

  - When using KVM, programming a PIT timer without a
    irqchip configuration, can be used to crash the kvm
    guest. This likely can be done only by a privileged
    guest user. (CVE-2011-4622)

  - A KVM 32bit guest crash in 'syscall' opcode handling was
    fixed that could be caused by local attackers.
    (CVE-2012-0045)

  - Fixed a oops in jbd/jbd2 that could be caused by
    specific filesystem access patterns. The following
    non-security issues have been fixed:. (CVE-2011-4086)

X86 :

  - x86: fix the initialization of physnode_map.
    (bnc#748112)

  - x86: Allow bootmem reserves at greater than 8G node
    offset within a node. (bnc#740895)

  - x86, tsc: Fix SMI induced variation in
    quick_pit_calibrate(). (bnc#751322)

  - x86, efi: Work around broken firmware. (bnc#714507)
    BONDING :

  - bonding: update speed/duplex for NETDEV_CHANGE.
    (bnc#752634)

  - bonding: comparing a u8 with -1 is always false.
    (bnc#752634)

  - bonding: start slaves with link down for ARP monitor.
    (bnc#752634)

  - bonding: send gratuitous ARP for all addresses
    (bnc#752491). XFS :

  - xfs: Fix excessive inode syncing when project quota is
    exceeded. (bnc#756448)

  - xfs: Fix oops on IO error during
    xlog_recover_process_iunlinks() (bnc#716850). SCSI :

  - scsi/ses: Handle non-unique element descriptors.
    (bnc#749342, bnc#617344)

  - scsi/sd: mark busy sd majors as allocated (bug#744658).

  - scsi: Check for invalid sdev in scsi_prep_state_check()
    (bnc#734300). MD/RAID :

  - md: fix possible corruption of array metadata on
    shutdown.

  - md: ensure changes to write-mostly are reflected in
    metadata. (bnc#755178)

  - md: do not set md arrays to readonly on shutdown
    (bnc#740180, bnc#713148, bnc#734900). XEN :

  - smpboot: adjust ordering of operations.

  - x86-64: provide a memset() that can deal with 4Gb or
    above at a time. (bnc#738528)

  - blkfront: properly fail packet requests. (bnc#745929)

  - Update Xen patches to 2.6.32.57.

  - xenbus: Reject replies with payload >
    XENSTORE_PAYLOAD_MAX.

  - xenbus_dev: add missing error checks to watch handling.

  - Refresh other Xen patches. (bnc#652942, bnc#668194,
    bnc#688079)

  - fix Xen-specific kABI issue in Linux 2.6.19. NFS :

  - NFSD: Fill in WCC data for REMOVE, RMDIR, MKNOD, and
    MKDIR. (bnc#751880)

  - nfs: Include SYNC flag when comparing mount options with
    NOAC flag. (bnc#745422)

  - NFS returns EIO for EDQUOT and others. (bnc#747028)

  - lockd: fix arg parsing for grace_period and timeout.
    (bnc#733761)

  - nfs: allow nfs4leasetime to be set before starting
    servers. (bnc#733761)

  - nfs: handle d_revalidate of dot correctly (bnc#731809).
    S/390 :

  - ctcmpc: use correct idal word list for ctcmpc
    (bnc#750171,LTC#79264).

  - qeth: synchronize discipline module loading
    (bnc#747430,LTC#78788).

  - qdio: avoid race leading to stall when tolerating CQ
    (bnc#737326,LTC#76599).

  - kernel: no storage key operations for invalid page table
    entries (bnc#737326,LTC#77697). OTHER :

  - tlan: add cast needed for proper 64 bit operation.
    (bnc#756840)

  - dl2k: Tighten ioctl permissions. (bnc#758813)

  - tg3: Fix RSS ring refill race condition. (bnc#757917)

  - usbhid: fix error handling of not enough bandwidth.
    (bnc#704280)

  - pagecache limit: Fix the shmem deadlock. (bnc#755537)

  - tty_audit: fix tty_audit_add_data live lock on audit
    disabled. (bnc#721366)

  - ixgbe: driver sets all WOL flags upon initialization so
    that machine is powered on as soon at it is switched
    off. (bnc#693639)

  - PCI: Set device power state to PCI_D0 for device without
    native PM support. (bnc#752972)

  - dlm: Do not allocate a fd for peeloff. (bnc#729247)

  - sctp: Export sctp_do_peeloff. (bnc#729247)

  - epoll: Do not limit non-nested epoll paths. (bnc#676204)

  - mlx4: Limit MSI-X vector allocation. (bnc#624072)

  - mlx4: Changing interrupt scheme. (bnc#624072)

  - mlx4_en: Assigning TX irq per ring. (bnc#624072)

  - mlx4_en: Restoring RX buffer pointer in case of failure.
    (bnc#624072)

  - mlx4_en: using new mlx4 interrupt scheme. (bnc#624072)

  - igb: Fix for Alt MAC Address feature on 82580 and later
    devices. (bnc#746980)

  - igb: Power down link when interface is down.
    (bnc#745699)

  - igb: use correct bits to identify if managability is
    enabled. (bnc#743209)

  - intel_agp: Do not oops with zero stolen memory.
    (bnc#738679)

  - agp: fix scratch page cleanup. (bnc#738679)

  - hugetlb: add generic definition of NUMA_NO_NODE.
    (bnc#751844)

  - sched: Fix proc_sched_set_task(). (bnc#717994)

  - PM: Print a warning if firmware is requested when tasks
    are frozen. (bnc#749886)

  - PM / Sleep: Fix freezer failures due to racy
    usermodehelper_is_disabled(). (bnc#749886)

  - PM / Sleep: Fix read_unlock_usermodehelper() call.
    (bnc#749886)

  - firmware loader: allow builtin firmware load even if
    usermodehelper is disabled. (bnc#749886)

  - PM / Hibernate: Enable usermodehelpers in
    software_resume() error path. (bnc#744163)

  - ipv6: Allow inet6_dump_addr() to handle more than 64
    addresses. (bnc#748279)

  - ipv6: fix refcnt problem related to POSTDAD state.
    (bnc#743619)

  - be2net: change to show correct physical link status.
    (bnc#727834)

  - be2net: changes to properly provide phy details.
    (bnc#727834)

  - aio: fix race between io_destroy() and io_submit().
    (bnc#747445 / bnc#611264)

  - intel-iommu: Check for identity mapping candidate using
    system dma mask. (bnc#700449)

  - intel-iommu: Dont cache iova above 32bit. (bnc#700449)

  - intel-iommu: Add domain check in
    domain_remove_one_dev_info. (bnc#700449)

  - intel-iommu: Provide option to enable 64-bit IOMMU pass
    through mode. (bnc#700449)

  - intel-iommu: Remove Host Bridge devices from identity
    mapping. (bnc#700449)

  - intel-iommu: Speed up processing of the identity_mapping
    function. (bnc#700449)

  - intel-iommu: Use coherent DMA mask when requested.
    (bnc#700449)

  - 1: Fix accounting of softirq time when idle.
    (bnc#719793)

  - driver-core: fix race between device_register and
    driver_register. (bnc#742358)

  - dcache: patches.fixes/large-hash-dcache_init-fix.patch:
    Fix oops when initializing large hash on > 16TB machine.
    (bnc#742210)

  - kdump: Save PG_compound or PG_head value in VMCOREINFO.
    (bnc#738503)

  - Update config files: disable NET_9P_RDMA. (bnc#720374)

  - cdc-wdm: fix race leading leading to memory corruption.
    (bnc#759544)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=611264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=617344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=624072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=652942"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=668194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=676204"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=688079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=693639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=697920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=700449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=713148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714507"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=717994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=719793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=720374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=721366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=727834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=729247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=731809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=734900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=737326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742210"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742358"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=743619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=747445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748279"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=748812"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750079"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751844"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=751880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756448"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758813"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=759544"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4622.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1090.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2133.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 6227 / 6229 / 6230 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:btrfs-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ext4dev-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hyper-v-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-desktop-devel");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-default-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-default-extra-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-desktop-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-pae-extra-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-source-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-syms-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-trace-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"kernel-xen-extra-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-default-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-default-extra-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-desktop-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-source-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-syms-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-trace-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"kernel-xen-extra-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"btrfs-kmp-default-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ext4dev-kmp-default-0_2.6.32.59_0.3-7.9.59")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"ext4dev-kmp-trace-0_2.6.32.59_0.3-7.9.59")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-default-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-source-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-syms-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"kernel-trace-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-pae-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"btrfs-kmp-xen-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-pae-0_2.6.32.59_0.3-7.9.59")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ext4dev-kmp-xen-0_2.6.32.59_0.3-7.9.59")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-default-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-pae-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"hyper-v-kmp-trace-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-ec2-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-ec2-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-ec2-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-pae-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"kernel-xen-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"kernel-default-man-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"btrfs-kmp-xen-0_2.6.32.59_0.3-0.3.92")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"ext4dev-kmp-xen-0_2.6.32.59_0.3-7.9.59")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-default-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"hyper-v-kmp-trace-0_2.6.32.59_0.3-0.18.16")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-ec2-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-ec2-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-ec2-devel-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-base-2.6.32.59-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"kernel-xen-devel-2.6.32.59-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
