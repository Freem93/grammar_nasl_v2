#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1174-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84545);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2014-8086", "CVE-2014-8159", "CVE-2014-9419", "CVE-2014-9529", "CVE-2014-9683", "CVE-2015-0777", "CVE-2015-1421", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3339", "CVE-2015-3636");
  script_bugtraq_id(70376, 71794, 71880, 72356, 72643, 72729, 72730, 73014, 73060, 73699, 73921, 74235, 74243, 74315, 74450);
  script_osvdb_id(113012, 116259, 116762, 117716, 118625, 118655, 118659, 119409, 119630, 120282, 120284, 120316, 121011, 121170, 121578);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2015:1174-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 Service Pack 3 kernel was updated to fix
various bugs and security issues.

The following vulnerabilities have been fixed :

CVE-2015-3636: A missing sk_nulls_node_init() in ping_unhash() inside
the ipv4 stack can cause crashes if a disconnect is followed by
another connect() attempt. (bnc#929525)

CVE-2015-3339: Race condition in the prepare_binprm function in
fs/exec.c in the Linux kernel before 3.19.6 allows local users to gain
privileges by executing a setuid program at a time instant when a
chown to root is in progress, and the ownership is changed but the
setuid bit is not yet stripped. (bnc#928130)

CVE-2015-3331: The __driver_rfc4106_decrypt function in
arch/x86/crypto/aesni-intel_glue.c in the Linux kernel before 3.19.3
does not properly determine the memory locations used for encrypted
data, which allows context-dependent attackers to cause a denial of
service (buffer overflow and system crash) or possibly execute
arbitrary code by triggering a crypto API call, as demonstrated by use
of a libkcapi test program with an AF_ALG(aead) socket. (bnc#927257)

CVE-2015-2922: The ndisc_router_discovery function in net/ipv6/ndisc.c
in the Neighbor Discovery (ND) protocol implementation in the IPv6
stack in the Linux kernel before 3.19.6 allows remote attackers to
reconfigure a hop-limit setting via a small hop_limit value in a
Router Advertisement (RA) message. (bnc#922583)

CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux kernel before
3.19.2 does not prevent the TS_COMPAT flag from reaching a user-mode
task, which might allow local users to bypass the seccomp or audit
protection mechanism via a crafted application that uses the (1) fork
or (2) close system call, as demonstrated by an attack against seccomp
before 3.16. (bnc#926240)

CVE-2015-2150: XSA-120: Xen 3.3.x through 4.5.x and the Linux kernel
through 3.19.1 do not properly restrict access to PCI command
registers, which might allow local guest users to cause a denial of
service (non-maskable interrupt and host crash) by disabling the (1)
memory or (2) I/O decoding for a PCI Express device and then accessing
the device, which triggers an Unsupported Request (UR) response.
(bnc#919463)

CVE-2015-2042: net/rds/sysctl.c in the Linux kernel before 3.19 uses
an incorrect data type in a sysctl table, which allows local users to
obtain potentially sensitive information from kernel memory or
possibly have unspecified other impact by accessing a sysctl entry.
(bnc#919018)

CVE-2015-2041: net/llc/sysctl_net_llc.c in the Linux kernel before
3.19 uses an incorrect data type in a sysctl table, which allows local
users to obtain potentially sensitive information from kernel memory
or possibly have unspecified other impact by accessing a sysctl entry.
(bnc#919007)

CVE-2015-1421: Use-after-free vulnerability in the sctp_assoc_update
function in net/sctp/associola.c in the Linux kernel before 3.18.8
allows remote attackers to cause a denial of service (slab corruption
and panic) or possibly have unspecified other impact by triggering an
INIT collision that leads to improper handling of shared-key data.
(bnc#915577)

CVE-2015-0777: drivers/xen/usbback/usbback.c in 1 -2.6.18-xen-3.4.0
(aka the Xen 3.4.x support patches for the Linux kernel 2.6.18), as
used in the Linux kernel 2.6.x and 3.x in SUSE Linux distributions,
allows guest OS users to obtain sensitive information from
uninitialized locations in host OS kernel memory via unspecified
vectors. (bnc#917830)

CVE-2014-9683: Off-by-one error in the ecryptfs_decode_from_filename
function in fs/ecryptfs/crypto.c in the eCryptfs subsystem in the
Linux kernel before 3.18.2 allows local users to cause a denial of
service (buffer overflow and system crash) or possibly gain privileges
via a crafted filename. (bnc#918333)

CVE-2014-9529: Race condition in the key_gc_unused_keys function in
security/keys/gc.c in the Linux kernel through 3.18.2 allows local
users to cause a denial of service (memory corruption or panic) or
possibly have unspecified other impact via keyctl commands that
trigger access to a key structure member during garbage collection of
a key. (bnc#912202)

CVE-2014-9419: The __switch_to function in
arch/x86/kernel/process_64.c in the Linux kernel through 3.18.1 does
not ensure that Thread Local Storage (TLS) descriptors are loaded
before proceeding with other steps, which makes it easier for local
users to bypass the ASLR protection mechanism via a crafted
application that reads a TLS base address. (bnc#911326)

CVE-2014-8159: The InfiniBand (IB) implementation in the Linux kernel
does not properly restrict use of User Verbs for registration of
memory regions, which allows local users to access arbitrary physical
memory locations, and consequently cause a denial of service (system
crash) or gain privileges, by leveraging permissions on a uverbs
device under /dev/infiniband/. (bnc#914742)

CVE-2014-8086: Race condition in the ext4_file_write_iter function in
fs/ext4/file.c in the Linux kernel through 3.17 allows local users to
cause a denial of service (file unavailability) via a combination of a
write action and an F_SETFL fcntl operation for the O_DIRECT flag.
(bnc#900881)

Also the following non-security bugs have been fixed :

mm: exclude reserved pages from dirtyable memory (bnc#931015,
bnc#930788).

mm: fix calculation of dirtyable memory (bnc#931015, bnc#930788).

mm/page-writeback.c: fix dirty_balance_reserve subtraction from
dirtyable memory (bnc#931015, bnc#930788).

mm, oom: fix and cleanup oom score calculations (bnc#930171).

mm: fix anon_vma->degree underflow in anon_vma endless growing
prevention (bnc#904242).

mm, slab: lock the correct nodelist after reenabling irqs
(bnc#926439).

x86: irq: Check for valid irq descriptor
incheck_irq_vectors_for_cpu_disable (bnc#914726).

x86/mce: Introduce mce_gather_info() (bsc#914987).

x86/mce: Fix mce regression from recent cleanup (bsc#914987).

x86/mce: Update MCE severity condition check (bsc#914987).

x86, kvm: Remove incorrect redundant assembly constraint (bnc#931850).

x86/reboot: Fix a warning message triggered by stop_other_cpus()
(bnc#930284).

x86/apic/uv: Update the UV APIC HUB check (bsc#929145).

x86/apic/uv: Update the UV APIC driver check (bsc#929145).

x86/apic/uv: Update the APIC UV OEM check (bsc#929145).

kabi: invalidate removed sys_elem_dir::children (bnc#919589).

kabi: fix for changes in the sysfs_dirent structure (bnc#919589).

iommu/amd: Correctly encode huge pages in iommu page tables
(bsc#931014).

iommu/amd: Optimize amd_iommu_iova_to_phys for new fetch_pte interface
(bsc#931014).

iommu/amd: Optimize alloc_new_range for new fetch_pte interface
(bsc#931014).

iommu/amd: Optimize iommu_unmap_page for new fetch_pte interface
(bsc#931014).

iommu/amd: Return the pte page-size in fetch_pte (bsc#931014).

rtc: Prevent the automatic reboot after powering off the system
(bnc#930145)

rtc: Restore the RTC alarm time to the configured alarm time in BIOS
Setup (bnc#930145, bnc#927262).

rtc: Add more TGCS models for alarm disable quirk (bnc#927262).

kernel: Fix IA64 kernel/kthread.c build woes. Hide #include
<1/hardirq.h> from kABI checker.

cpu: Correct cpu affinity for dlpar added cpus (bsc#928970).

proc: deal with deadlock in d_walk fix (bnc#929148, bnc#929283).

proc: /proc/stat: convert to single_open_size() (bnc#928122).

proc: new helper: single_open_size() (bnc#928122).

proc: speed up /proc/stat handling (bnc#928122).

sched: Fix potential near-infinite distribute_cfs_runtime() loop
(bnc#930786)

tty: Correct tty buffer flush (bnc#929647).

tty: hold lock across tty buffer finding and buffer filling
(bnc#929647).

fork: report pid reservation failure properly (bnc#909684).

random: Fix add_timer_randomness throttling
(bsc#904883,bsc#904901,FATE#317374).

random: account for entropy loss due to overwrites (FATE#317374).

random: allow fractional bits to be tracked (FATE#317374).

random: statically compute poolbitshift, poolbytes, poolbits
(FATE#317374).

crypto: Limit allocation of crypto mechanisms to dialect which
requires (bnc#925729).

net: relax rcvbuf limits (bug#923344).

udp: only allow UFO for packets from SOCK_DGRAM sockets (bnc#909309).

acpi / sysfs: Treat the count field of counter_show() as unsigned
(bnc#909312).

acpi / osl: speedup grace period in acpi_os_map_cleanup (bnc#877456).

btrfs: upstream fixes from 3.18

btrfs: fix race when reusing stale extent buffers that leads to
BUG_ON.

btrfs: btrfs_release_extent_buffer_page did not free pages of dummy
extent (bnc#930226, bnc#916521).

btrfs: set error return value in btrfs_get_blocks_direct.

btrfs: fix off-by-one in cow_file_range_inline().

btrfs: wake up transaction thread from SYNC_FS ioctl.

btrfs: fix wrong fsid check of scrub.

btrfs: try not to ENOSPC on log replay.

btrfs: fix build_backref_tree issue with multiple shared blocks.

btrfs: add missing end_page_writeback on submit_extent_page failure.

btrfs: fix crash of btrfs_release_extent_buffer_page.

btrfs: fix race in WAIT_SYNC ioctl.

btrfs: fix kfree on list_head in btrfs_lookup_csums_range error
cleanup.

btrfs: cleanup orphans while looking up default subvolume
(bsc#914818).

btrfs: fix lost return value due to variable shadowing.

btrfs: abort the transaction if we fail to update the free space cache
inode.

btrfs: fix scheduler warning when syncing log.

btrfs: add more checks to btrfs_read_sys_array.

btrfs: cleanup, rename a few variables in btrfs_read_sys_array.

btrfs: add checks for sys_chunk_array sizes.

btrfs: more superblock checks, lower bounds on devices and
sectorsize/nodesize.

btrfs: fix setup_leaf_for_split() to avoid leaf corruption.

btrfs: fix typos in btrfs_check_super_valid.

btrfs: use macro accessors in superblock validation checks.

btrfs: add more superblock checks.

btrfs: avoid premature -ENOMEM in clear_extent_bit().

btrfs: avoid returning -ENOMEM in convert_extent_bit() too early.

btrfs: call inode_dec_link_count() on mkdir error path.

btrfs: fix fs corruption on transaction abort if device supports
discard.

btrfs: make sure we wait on logged extents when fsycning two subvols.

btrfs: make xattr replace operations atomic.

xfs: xfs_alloc_fix_minleft can underflow near ENOSPC (bnc#913080,
bnc#912741).

xfs: prevent deadlock trying to cover an active log (bsc#917093).

xfs: introduce xfs_bmapi_read() (bnc#891641).

xfs: factor extent map manipulations out of xfs_bmapi (bnc#891641).

nfs: Fix a regression in nfs_file_llseek() (bnc#930401).

nfs: do not try to use lock state when we hold a delegation
(bnc#831029) - add to series.conf

sunrpc: Fix the execution time statistics in the face of RPC restarts
(bnc#924271).

fsnotify: Fix handling of renames in audit (bnc#915200).

configfs: fix race between dentry put and lookup (bnc#924333).

fs/pipe.c: add ->statfs callback for pipefs (bsc#916848).

fs/buffer.c: make block-size be per-page and protected by the page
lock (bnc#919357).

st: fix corruption of the st_modedef structures in st_set_options()
(bnc#928333).

lpfc: Fix race on command completion (bnc#906027,bnc#889221).

cifs: fix use-after-free bug in find_writable_file (bnc#909477).

sysfs: Make sysfs_rename safe with sysfs_dirents in rbtrees
(bnc#919589).

sysfs: use rb-tree for inode number lookup (bnc#919589).

sysfs: use rb-tree for name lookups (bnc#919589).

dasd: Fix inability to set a DASD device offline (bnc#927338,
LTC#123905).

dasd: Fix device having no paths after suspend/resume (bnc#927338,
LTC#123896).

dasd: Fix unresumed device after suspend/resume (bnc#927338,
LTC#123892).

dasd: Missing partition after online processing (bnc#917120,
LTC#120565).

af_iucv: fix AF_IUCV sendmsg() errno (bnc#927338, LTC#123304).

s390: avoid z13 cache aliasing (bnc#925012).

s390: enable large page support with CONFIG_DEBUG_PAGEALLOC
(bnc#925012).

s390: z13 base performance (bnc#925012, LTC#KRN1514).

s390/spinlock: cleanup spinlock code (bnc#925012).

s390/spinlock: optimize spinlock code sequence (bnc#925012).

s390/spinlock,rwlock: always to a load-and-test first (bnc#925012).

s390/spinlock: refactor arch_spin_lock_wait[_flags] (bnc#925012).

s390/spinlock: optimize spin_unlock code (bnc#925012).

s390/rwlock: add missing local_irq_restore calls (bnc#925012).

s390/time: use stck clock fast for do_account_vtime (bnc#925012).

s390/kernel: use stnsm 255 instead of stosm 0 (bnc#925012).

s390/mm: align 64-bit PIE binaries to 4GB (bnc#925012).

s390/mm: use pfmf instruction to initialize storage keys (bnc#925012).

s390/mm: speedup storage key initialization (bnc#925012).

s390/memory hotplug: initialize storage keys (bnc#925012).

s390/memory hotplug: use pfmf instruction to initialize storage keys
(bnc#925012).

s390/facilities: cleanup PFMF and HPAGE machine facility detection
(bnc#925012).

powerpc/perf: Cap 64bit userspace backtraces to PERF_MAX_STACK_DEPTH
(bsc#928142).

powerpc+sparc64/mm: Remove hack in mmap randomize layout (bsc#917839).

powerpc: Make chip-id information available to userspace (bsc#919682).

powerpc/mm: Fix mmap errno when MAP_FIXED is set and mapping exceeds
the allowed address space (bsc#930669).

ib/ipoib: Add missing locking when CM object is deleted (bsc#924340).

ib/ipoib: Fix RCU pointer dereference of wrong object (bsc#924340).

IPoIB: Fix race in deleting ipoib_neigh entries (bsc#924340).

IPoIB: Fix ipoib_neigh hashing to use the correct daddr octets
(bsc#924340).

IPoIB: Fix AB-BA deadlock when deleting neighbours (bsc#924340).

IPoIB: Fix memory leak in the neigh table deletion flow (bsc#924340).

ch: fixup refcounting imbalance for SCSI devices (bsc#925443).

ch: remove ch_mutex (bnc#925443).

DLPAR memory add failed on Linux partition (bsc#927190).

Revert 'pseries/iommu: Remove DDW on kexec' (bsc#926016).

Revert 'powerpc/pseries/iommu: remove default window before attempting
DDW manipulation' (bsc#926016).

alsa: hda_intel: apply the Separate stream_tag for Sunrise Point
(bsc#925370).

alsa: hda_intel: apply the Separate stream_tag for Skylake
(bsc#925370).

alsa: hda_controller: Separate stream_tag for input and output streams
(bsc#925370).

md: do not give up looking for spares on first failure-to-add
(bnc#908706).

md: fix safe_mode buglet (bnc#926767).

md: do not wait for plug_cnt to go to zero (bnc#891641).

epoll: fix use-after-free in eventpoll_release_file (epoll scaling).

eventpoll: use-after-possible-free in epoll_create1() (bug#917648).

direct-io: do not read inode->i_blkbits multiple times (bnc#919357).

scsifront: do not use bitfields for indicators modified under
different locks.

msi: also reject resource with flags all clear.

pvscsi: support suspend/resume (bsc#902286).

Do not switch internal CDC device on IBM NeXtScale nx360 M5
(bnc#913598).

dm: optimize use SRCU and RCU (bnc#910517).

uvc: work on XHCI controllers without ring expansion (bnc#915045).

qla2xxx: Do not crash system for sp ref count zero
(bnc#891212,bsc#917684).

megaraid_sas : Update threshold based reply post host index register
(bnc#919808).

bnx2x: Fix kdump when iommu=on (bug#921769).

Provide/Obsolete all subpackages of old flavors (bnc#925567)

tgcs: Ichigan 6140-x3x Integrated touchscreen is not precised
(bnc#924142).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/831029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/877456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/889221"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/891212"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/891641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/900881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/904901"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/906027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908706"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910517"
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
    value:"https://bugzilla.suse.com/912741"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914726"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915045"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917648"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919808"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922583"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925729"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928970"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930401"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930788"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931850"
  );
  # https://download.suse.com/patch/finder/?keywords=03bfa6c75cb5a4cc6051fbc3690140d3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1c8e5da"
  );
  # https://download.suse.com/patch/finder/?keywords=33f906d57c7adfdab2c5c7c702cdcc35
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f0219dd"
  );
  # https://download.suse.com/patch/finder/?keywords=3e0de0ca574129367fbd700f1fcd6a34
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15a25b8b"
  );
  # https://download.suse.com/patch/finder/?keywords=613faa6f2a4360fe9998cf1191971acd
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58b62ba1"
  );
  # https://download.suse.com/patch/finder/?keywords=75c42977aa44422b8e12040ea373b902
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?631f6767"
  );
  # https://download.suse.com/patch/finder/?keywords=81a75ad520ef4ea9b9c573a7a188dc57
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58f65758"
  );
  # https://download.suse.com/patch/finder/?keywords=8c54aaa27bf9a5984cc9911a7413d962
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef02f47f"
  );
  # https://download.suse.com/patch/finder/?keywords=ad2768d3cc62a7649f30b1411b1594c7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84917562"
  );
  # https://download.suse.com/patch/finder/?keywords=ba8477a089d848b7d15e1cde80ddf9a0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0db92481"
  );
  # https://download.suse.com/patch/finder/?keywords=eafe120fa23e6b5da6394f829b734878
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f112eac1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8086.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8159.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9419.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9529.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9683.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1421.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2041.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2150.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2830.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2922.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3331.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3636.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151174-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a0a953a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP3 for VMware :

zypper in -t patch slessp3-kernel=10717 slessp3-kernel=10740

SUSE Linux Enterprise Server 11 SP3 :

zypper in -t patch slessp3-kernel=10717 slessp3-kernel=10718
slessp3-kernel=10719 slessp3-kernel=10720 slessp3-kernel=10740

SUSE Linux Enterprise High Availability Extension 11 SP3 :

zypper in -t patch slehasp3-kernel=10717 slehasp3-kernel=10718
slehasp3-kernel=10719 slehasp3-kernel=10720 slehasp3-kernel=10740

SUSE Linux Enterprise Desktop 11 SP3 :

zypper in -t patch sledsp3-kernel=10717 sledsp3-kernel=10740

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/06");
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
if (! ereg(pattern:"^(SLED11|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED11 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-source-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-syms-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-source-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-syms-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-default-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.55.1")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"xen-kmp-pae-4.2.5_08_3.0.101_0.47.55-0.7.1")) flag++;


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
