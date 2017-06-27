#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0529-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83702);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2014-3673", "CVE-2014-3687", "CVE-2014-7822", "CVE-2014-7841", "CVE-2014-8160", "CVE-2014-8559", "CVE-2014-9419", "CVE-2014-9584");
  script_bugtraq_id(70766, 70854, 70883, 71081, 71794, 71883, 72061, 72347);
  script_osvdb_id(113724, 113727, 114044, 114575, 116259, 116767, 117131, 117810);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2015:0529-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to 3.12.38 to receive
various security and bugfixes.

This update contains the following feature enablements :

  - The remote block device (rbd) and ceph drivers have been
    enabled and are now supported. (FATE#318350) These can
    be used e.g. for accessing the SUSE Enterprise Storage
    product services.

  - Support for Intel Select Bay trail CPUs has been added.
    (FATE#316038)

Following security issues were fixed :

  - CVE-2014-9419: The __switch_to function in
    arch/x86/kernel/process_64.c in the Linux kernel through
    3.18.1 did not ensure that Thread Local Storage (TLS)
    descriptors were loaded before proceeding with other
    steps, which made it easier for local users to bypass
    the ASLR protection mechanism via a crafted application
    that reads a TLS base address (bnc#911326).

  - CVE-2014-7822: A flaw was found in the way the Linux
    kernels splice() system call validated its parameters.
    On certain file systems, a local, unprivileged user
    could have used this flaw to write past the maximum file
    size, and thus crash the system.

  - CVE-2014-8160: The connection tracking module could be
    bypassed if a specific protocol module was not loaded,
    e.g. allowing SCTP traffic while the firewall should
    have filtered it.

  - CVE-2014-9584: The parse_rock_ridge_inode_internal
    function in fs/isofs/rock.c in the Linux kernel before
    3.18.2 did not validate a length value in the Extensions
    Reference (ER) System Use Field, which allowed local
    users to obtain sensitive information from kernel memory
    via a crafted iso9660 image (bnc#912654).

The following non-security bugs were fixed :

  - audit: Allow login in non-init namespaces (bnc#916107).

  - btrfs: avoid unnecessary switch of path locks to
    blocking mode.

  - btrfs: fix directory inconsistency after fsync log
    replay (bnc#915425).

  - btrfs: fix fsync log replay for inodes with a mix of
    regular refs and extrefs (bnc#915425).

  - btrfs: fix fsync race leading to ordered extent memory
    leaks (bnc#917128).

  - btrfs: fix fsync when extend references are added to an
    inode (bnc#915425).

  - btrfs: fix missing error handler if submiting re-read
    bio fails.

  - btrfs: fix race between transaction commit and empty
    block group removal (bnc#915550).

  - btrfs: fix scrub race leading to use-after-free
    (bnc#915456).

  - btrfs: fix setup_leaf_for_split() to avoid leaf
    corruption (bnc#915454).

  - btrfs: improve free space cache management and space
    allocation.

  - btrfs: make btrfs_search_forward return with nodes
    unlocked.

  - btrfs: scrub, fix sleep in atomic context (bnc#915456).

  - btrfs: unlock nodes earlier when inserting items in a
    btree.

  - drm/i915: On G45 enable cursor plane briefly after
    enabling the display plane (bnc#918161).

  - Fix Module.supported handling for external modules
    (bnc#905304).

  - keys: close race between key lookup and freeing
    (bnc#912202).

  - msi: also reject resource with flags all clear.

  - pci: Add ACS quirk for Emulex NICs (bug#917089).

  - pci: Add ACS quirk for Intel 10G NICs (bug#917089).

  - pci: Add ACS quirk for Solarflare SFC9120 & SFC9140
    (bug#917089).

  - Refresh other Xen patches (bsc#909829).

  - Update
    patches.suse/btrfs-8177-improve-free-space-cache-managem
    ent-and-space-.patc h (bnc#895805).

  - be2net: avoid flashing SH-B0 UFI image on SH-P2 chip
    (bug#908322).

  - be2net: refactor code that checks flash file
    compatibility (bug#908322).

  - ceph: Add necessary clean up if invalid reply received
    in handle_reply() (bsc#918255).

  - crush: CHOOSE_LEAF -> CHOOSELEAF throughout
    (bsc#918255).

  - crush: add SET_CHOOSE_TRIES rule step (bsc#918255).

  - crush: add note about r in recursive choose
    (bsc#918255).

  - crush: add set_choose_local_[fallback_]tries steps
    (bsc#918255).

  - crush: apply chooseleaf_tries to firstn mode too
    (bsc#918255).

  - crush: attempts -> tries (bsc#918255).

  - crush: clarify numrep vs endpos (bsc#918255).

  - crush: eliminate CRUSH_MAX_SET result size limitation
    (bsc#918255).

  - crush: factor out (trivial) crush_destroy_rule()
    (bsc#918255).

  - crush: fix crush_choose_firstn comment (bsc#918255).

  - crush: fix some comments (bsc#918255).

  - crush: generalize descend_once (bsc#918255).

  - crush: new SET_CHOOSE_LEAF_TRIES command (bsc#918255).

  - crush: pass parent r value for indep call (bsc#918255).

  - crush: pass weight vector size to map function
    (bsc#918255).

  - crush: reduce scope of some local variables
    (bsc#918255).

  - crush: return CRUSH_ITEM_UNDEF for failed placements
    with indep (bsc#918255).

  - crush: strip firstn conditionals out of crush_choose,
    rename (bsc#918255).

  - crush: use breadth-first search for indep mode
    (bsc#918255).

  - crypto: drbg - panic on continuous self test error
    (bsc#905482).

  - dasd: List corruption in error recovery (bnc#914291,
    LTC#120865).

  - epoll: optimize setting task running after blocking
    (epoll-performance).

  - fips: We need to activate gcm(aes) in FIPS mode, RFCs
    4106 and 4543 (bsc#914126,bsc#914457).

  - fips: __driver-gcm-aes-aesni needs to be listed
    explicitly inside the testmgr.c file (bsc#914457).

  - flow_dissector: add tipc support (bnc#916513).

  - hotplug, powerpc, x86: Remove cpu_hotplug_driver_lock()
    (bsc#907069).

  - hyperv: Add support for vNIC hot removal.

  - kernel: incorrect clock_gettime result (bnc#914291,
    LTC#121184).

  - kvm: iommu: Add cond_resched to legacy device assignment
    code (bsc#898687).

  - libceph: CEPH_OSD_FLAG_* enum update (bsc#918255).

  - libceph: add ceph_kv{malloc,free}() and switch to them
    (bsc#918255).

  - libceph: add ceph_pg_pool_by_id() (bsc#918255).

  - libceph: all features fields must be u64 (bsc#918255).

  - libceph: dout() is missing a newline (bsc#918255).

  - libceph: factor out logic from ceph_osdc_start_request()
    (bsc#918255).

  - libceph: fix error handling in ceph_osdc_init()
    (bsc#918255).

  - libceph: follow redirect replies from osds (bsc#918255).

  - libceph: follow {read,write}_tier fields on osd request
    submission (bsc#918255).

  - libceph: introduce and start using oid abstraction
    (bsc#918255).

  - libceph: rename MAX_OBJ_NAME_SIZE to
    CEPH_MAX_OID_NAME_LEN (bsc#918255).

  - libceph: rename ceph_osd_request::r_{oloc,oid} to
    r_base_{oloc,oid} (bsc#918255).

  - libceph: replace ceph_calc_ceph_pg() with
    ceph_oloc_oid_to_pg() (bsc#918255).

  - libceph: start using oloc abstraction (bsc#918255).

  - libceph: take map_sem for read in handle_reply()
    (bsc#918255).

  - libceph: update ceph_features.h (bsc#918255).

  - libceph: use CEPH_MON_PORT when the specified port is 0
    (bsc#918255).

  - locking/mutex: Explicitly mark task as running after
    wakeup (mutex scalability).

  - locking/osq: No need for load/acquire when
    acquire-polling (mutex scalability).

  - locking/rtmutex: Optimize setting task running after
    being blocked (mutex scalability).

  - mm/compaction: fix wrong order check in
    compact_finished() (VM Performance, bnc#904177).

  - mm/compaction: stop the isolation when we isolate enough
    freepage (VM Performance, bnc#904177).

  - mm: fix negative nr_isolated counts (VM Performance).

  - mutex-debug: Always clear owner field upon
    mutex_unlock() (mutex bugfix).

  - net: 8021q/bluetooth/bridge/can/ceph: Remove extern from
    function prototypes (bsc#918255).

  - net: allow macvlans to move to net namespace
    (bnc#915660).

  - net:socket: set msg_namelen to 0 if msg_name is passed
    as NULL in msghdr struct from userland (bnc#900270).

  - nfs_prime_dcache needs fh to be set (bnc#908069
    bnc#896484).

  - ocfs2: remove filesize checks for sync I/O journal
    commit (bnc#800255). Update references.

  - powerpc/xmon: Fix another endiannes issue in RTAS call
    from xmon (bsc#915188).

  - pvscsi: support suspend/resume (bsc#902286).

  - random: account for entropy loss due to overwrites
    (bsc#904883,bsc#904901).

  - random: allow fractional bits to be tracked
    (bsc#904883,bsc#904901).

  - random: statically compute poolbitshift, poolbytes,
    poolbits (bsc#904883,bsc#904901).

  - rbd: add '^A' sysfs rbd device attribute (bsc#918255).

  - rbd: add support for single-major device number
    allocation scheme (bsc#918255).

  - rbd: enable extended devt in single-major mode
    (bsc#918255).

  - rbd: introduce rbd_dev_header_unwatch_sync() and switch
    to it (bsc#918255).

  - rbd: rbd_device::dev_id is an int, format it as such
    (bsc#918255).

  - rbd: refactor rbd_init() a bit (bsc#918255).

  - rbd: switch to ida for rbd id assignments (bsc#918255).

  - rbd: tear down watch request if rbd_dev_device_setup()
    fails (bsc#918255).

  - rbd: tweak 'loaded' message and module description
    (bsc#918255).

  - rbd: wire up is_visible() sysfs callback for rbd bus
    (bsc#918255).

  - rpm/kernel-binary.spec.in: Own the modules directory in
    the devel package (bnc#910322)

  - s390/dasd: fix infinite loop during format (bnc#914291,
    LTC#120608).

  - s390/dasd: remove unused code (bnc#914291, LTC#120608).

  - sched/Documentation: Remove unneeded word (mutex
    scalability).

  - sched/completion: Add lock-free checking of the blocking
    case (scheduler scalability).

  - scsifront: avoid acquiring same lock twice if ring is
    full.

  - scsifront: do not use bitfields for indicators modified
    under different locks.

  - swiotlb: Warn on allocation failure in
    swiotlb_alloc_coherent (bsc#905783).

  - uas: Add NO_ATA_1X for VIA VL711 devices (bnc#914254).

  - uas: Add US_FL_NO_ATA_1X for 2 more Seagate disk
    enclosures (bnc#914254).

  - uas: Add US_FL_NO_ATA_1X for Seagate devices with usb-id
    0bc2:a013 (bnc#914254).

  - uas: Add US_FL_NO_ATA_1X quirk for 1 more Seagate model
    (bnc#914254).

  - uas: Add US_FL_NO_ATA_1X quirk for 2 more Seagate models
    (bnc#914254).

  - uas: Add US_FL_NO_ATA_1X quirk for Seagate (0bc2:ab20)
    drives (bnc#914254).

  - uas: Add a quirk for rejecting ATA_12 and ATA_16
    commands (bnc#914254).

  - uas: Add missing le16_to_cpu calls to asm1051 / asm1053
    usb-id check (bnc#914294).

  - uas: Add no-report-opcodes quirk (bnc#914254).

  - uas: Disable uas on ASM1051 devices (bnc#914294).

  - uas: Do not blacklist ASM1153 disk enclosures
    (bnc#914294).

  - uas: Use streams on upcoming 10Gbps / 3.1 USB
    (bnc#914464).

  - uas: disable UAS on Apricorn SATA dongles (bnc#914300).

  - usb-storage: support for more than 8 LUNs (bsc#906196).

  - x86, crash: Allocate enough low-mem when
    crashkernel=high (bsc#905783).

  - x86, crash: Allocate enough low-mem when
    crashkernel=high (bsc#905783).

  - x86, swiotlb: Try coherent allocations with __GFP_NOWARN
    (bsc#905783).

  - x86/hpet: Make boot_hpet_disable extern (bnc#916646).

  - x86/intel: Add quirk to disable HPET for the Baytrail
    platform (bnc#916646).

  - x86: irq: Check for valid irq descriptor
    incheck_irq_vectors_for_cpu_disable (bnc#914726).

  - x86: irq: Check for valid irq descriptor in
    check_irq_vectors_for_cpu_disable (bnc#914726).

  - xhci: Add broken-streams quirk for Fresco Logic FL1000G
    xhci controllers (bnc#914112).

  - zcrypt: Number of supported ap domains is not
    retrievable (bnc#914291, LTC#120788).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
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
    value:"http://support.novell.com/security/cve/CVE-2014-7822.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-7841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8160.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8559.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9584.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/799216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/800255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/860346"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/875220"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/877456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/895805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/896484"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/897736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/898687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/900270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902286"
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
    value:"https://bugzilla.suse.com/903640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904899"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905100"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905329"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905482"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/906196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908825"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/912202"
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
    value:"https://bugzilla.suse.com/913059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915335"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915425"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917089"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917128"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918161"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918255"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150529-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75cca7a0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-130=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-130=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-130=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-130=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-130=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-130=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/20");
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
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.38-44.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.38-44.1")) flag++;


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
