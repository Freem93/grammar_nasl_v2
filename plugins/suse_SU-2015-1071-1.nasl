#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1071-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(84227);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/05/11 13:40:22 $");

  script_cve_id("CVE-2014-3647", "CVE-2014-8086", "CVE-2014-8159", "CVE-2015-1465", "CVE-2015-2041", "CVE-2015-2042", "CVE-2015-2666", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3331", "CVE-2015-3332", "CVE-2015-3339", "CVE-2015-3636");
  script_bugtraq_id(70376, 70748, 72435, 72729, 72730, 73060, 73183, 73699, 74232, 74235, 74243, 74315, 74450);
  script_osvdb_id(113012, 113899, 117916, 118655, 118659, 119630, 119873, 120282, 120284, 121011, 121170, 121578);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2015:1071-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to version 3.12.43 to
receive various security and bugfixes.

Following security bugs were fixed :

  - CVE-2014-3647: arch/x86/kvm/emulate.c in the KVM
    subsystem in the Linux kernel through 3.17.2 did not
    properly perform RIP changes, which allowed guest OS
    users to cause a denial of service (guest OS crash) via
    a crafted application (bsc#899192).

  - CVE-2014-8086: Race condition in the
    ext4_file_write_iter function in fs/ext4/file.c in the
    Linux kernel through 3.17 allowed local users to cause a
    denial of service (file unavailability) via a
    combination of a write action and an F_SETFL fcntl
    operation for the O_DIRECT flag (bsc#900881).

  - CVE-2014-8159: The InfiniBand (IB) implementation did
    not properly restrict use of User Verbs for registration
    of memory regions, which allowed local users to access
    arbitrary physical memory locations, and consequently
    cause a denial of service (system crash) or gain
    privileges, by leveraging permissions on a uverbs device
    under /dev/infiniband/ (bsc#914742).

  - CVE-2015-1465: The IPv4 implementation in the Linux
    kernel before 3.18.8 did not properly consider the
    length of the Read-Copy Update (RCU) grace period for
    redirecting lookups in the absence of caching, which
    allowed remote attackers to cause a denial of service
    (memory consumption or system crash) via a flood of
    packets (bsc#916225).

  - CVE-2015-2041: net/llc/sysctl_net_llc.c in the Linux
    kernel before 3.19 used an incorrect data type in a
    sysctl table, which allowed local users to obtain
    potentially sensitive information from kernel memory or
    possibly have unspecified other impact by accessing a
    sysctl entry (bsc#919007).

  - CVE-2015-2042: net/rds/sysctl.c in the Linux kernel
    before 3.19 used an incorrect data type in a sysctl
    table, which allowed local users to obtain potentially
    sensitive information from kernel memory or possibly
    have unspecified other impact by accessing a sysctl
    entry (bsc#919018).

  - CVE-2015-2666: Fixed a flaw that allowed crafted
    microcode to overflow the kernel stack (bsc#922944).

  - CVE-2015-2830: Fixed int80 fork from 64-bit tasks
    mishandling (bsc#926240).

  - CVE-2015-2922: Fixed possible denial of service (DoS)
    attack against IPv6 network stacks due to improper
    handling of Router Advertisements (bsc#922583).

  - CVE-2015-3331: Fixed buffer overruns in RFC4106
    implementation using AESNI (bsc#927257).

  - CVE-2015-3332: Fixed TCP Fast Open local DoS
    (bsc#928135).

  - CVE-2015-3339: Fixed race condition flaw between the
    chown() and execve() system calls which could have lead
    to local privilege escalation (bsc#928130).

  - CVE-2015-3636: Fixed use-after-free in ping sockets
    which could have lead to local privilege escalation
    (bsc#929525).

The following non-security bugs were fixed :

  - /proc/stat: convert to single_open_size() (bsc#928122).

  - ACPI / sysfs: Treat the count field of counter_show() as
    unsigned (bsc#909312).

  - Automatically Provide/Obsolete all subpackages of old
    flavors (bsc#925567)

  - Btrfs: btrfs_release_extent_buffer_page did not free
    pages of dummy extent (bsc#930226).

  - Btrfs: fix inode eviction infinite loop after cloning
    into it (bsc#930224).

  - Btrfs: fix inode eviction infinite loop after
    extent_same ioctl (bsc#930224).

  - Btrfs: fix log tree corruption when fs mounted with -o
    discard (bsc#927116).

  - Btrfs: fix up bounds checking in lseek (bsc#927115).

  - Fix rtworkqueues crash. Calling __sched_setscheduler()
    in interrupt context is forbidden, and destroy_worker()
    did so in the timer interrupt with a nohz_full config.
    Preclude that possibility for both boot options.

  - Input: psmouse - add psmouse_matches_pnp_id helper
    function (bsc#929092).

  - Input: synaptics - fix middle button on Lenovo 2015
    products (bsc#929092).

  - Input: synaptics - handle spurious release of trackstick
    buttons (bsc#929092).

  - Input: synaptics - re-route tracksticks buttons on the
    Lenovo 2015 series (bsc#929092).

  - Input: synaptics - remove TOPBUTTONPAD property for
    Lenovos 2015 (bsc#929092).

  - Input: synaptics - retrieve the extended capabilities in
    query $10 (bsc#929092).

  - NFS: Add attribute update barriers to
    nfs_setattr_update_inode() (bsc#920262).

  - NFS: restore kabi after change to
    nfs_setattr_update_inode (bsc#920262).

  - af_iucv: fix AF_IUCV sendmsg() errno (bsc#927308,
    LTC#123304).

  - audit: do not reject all AUDIT_INODE filter types
    (bsc#927455).

  - bnx2x: Fix kdump when iommu=on (bsc#921769).

  - cpufreq: fix a NULL pointer dereference in
    __cpufreq_governor() (bsc#924664).

  - dasd: Fix device having no paths after suspend/resume
    (bsc#927308, LTC#123896).

  - dasd: Fix inability to set a DASD device offline
    (bsc#927308, LTC#123905).

  - dasd: Fix unresumed device after suspend/resume
    (bsc#927308, LTC#123892).

  - dasd: Missing partition after online processing
    (bsc#917125, LTC#120565).

  - drm/radeon/cik: Add macrotile mode array query
    (bsc#927285).

  - drm/radeon: fix display tiling setup on SI (bsc#927285).

  - drm/radeon: set correct number of banks for CIK chips in
    DCE (bsc#927285).

  - iommu/amd: Correctly encode huge pages in iommu page
    tables (bsc#931014).

  - iommu/amd: Optimize alloc_new_range for new fetch_pte
    interface (bsc#931014).

  - iommu/amd: Optimize amd_iommu_iova_to_phys for new
    fetch_pte interface (bsc#931014).

  - iommu/amd: Optimize iommu_unmap_page for new fetch_pte
    interface (bsc#931014).

  - iommu/amd: Return the pte page-size in fetch_pte
    (bsc#931014).

  - ipc/shm.c: fix overly aggressive shmdt() when calls span
    multiple segments (ipc fixes).

  - ipmi: Turn off all activity on an idle ipmi interface
    (bsc#915540).

  - ixgbe: fix detection of SFP+ capable interfaces
    (bsc#922734).

  - kgr: add error code to the message in
    kgr_revert_replaced_funs.

  - kgr: add kgraft annotations to kthreads
    wait_event_freezable() API calls.

  - kgr: correct error handling of the first patching stage.

  - kgr: handle the delayed patching of the modules.

  - kgr: handle the failure of finalization stage.

  - kgr: return error in kgr_init if notifier registration
    fails.

  - kgr: take switching of the fops out of kgr_patch_code to
    new function.

  - kgr: use for_each_process_thread (bsc#929883).

  - kgr: use kgr_in_progress for all threads (bnc#929883).

  - libata: Blacklist queued TRIM on Samsung SSD 850 Pro
    (bsc#926156).

  - mlx4: Call dev_kfree_skby_any instead of dev_kfree_skb
    (bsc#928708).

  - mm, numa: really disable NUMA balancing by default on
    single node machines (Automatic NUMA Balancing).

  - mm: vmscan: do not throttle based on pfmemalloc reserves
    if node has no reclaimable pages (bsc#924803, VM
    Functionality).

  - net/mlx4: Cache line CQE/EQE stride fixes (bsc#927084).

  - net/mlx4_core: Cache line EQE size support (bsc#927084).

  - net/mlx4_core: Enable CQE/EQE stride support
    (bsc#927084).

  - net/mlx4_en: Add mlx4_en_get_cqe helper (bsc#927084).

  - perf/x86/amd/ibs: Update IBS MSRs and feature
    definitions.

  - powerpc/mm: Fix mmap errno when MAP_FIXED is set and
    mapping exceeds the allowed address space (bsc#930669).

  - powerpc/numa: Add ability to disable and debug topology
    updates (bsc#924809).

  - powerpc/numa: Enable CONFIG_HAVE_MEMORYLESS_NODES
    (bsc#924809).

  - powerpc/numa: Enable USE_PERCPU_NUMA_NODE_ID
    (bsc#924809).

  - powerpc/numa: check error return from proc_create
    (bsc#924809).

  - powerpc/numa: ensure per-cpu NUMA mappings are correct
    on topology update (bsc#924809).

  - powerpc/numa: use cached value of update->cpu in
    update_cpu_topology (bsc#924809).

  - powerpc/perf: Cap 64bit userspace backtraces to
    PERF_MAX_STACK_DEPTH (bsc#928141).

  - powerpc/pseries: Introduce api_version to migration
    sysfs interface (bsc#926314).

  - powerpc/pseries: Little endian fixes for post mobility
    device tree update (bsc#926314).

  - powerpc/pseries: Simplify check for suspendability
    during suspend/migration (bsc#926314).

  - powerpc: Fix sys_call_table declaration to enable
    syscall tracing.

  - powerpc: Fix warning reported by
    verify_cpu_node_mapping() (bsc#924809).

  - powerpc: Only set numa node information for present cpus
    at boottime (bsc#924809).

  - powerpc: reorder per-cpu NUMA information initialization
    (bsc#924809).

  - powerpc: some changes in numa_setup_cpu() (bsc#924809).

  - quota: Fix use of units in quota getting / setting
    interfaces (bsc#913232).

  - rpm/kernel-binary.spec.in: Fix build if there is no
    *.crt file

  - rpm/kernel-obs-qa.spec.in: Do not fail if the kernel
    versions do not match

  - s390/bpf: Fix ALU_NEG (A = -A) (bsc#917125, LTC#121759).

  - s390/bpf: Fix JMP_JGE_K (A >= K) and JMP_JGT_K (A > K)
    (bsc#917125, LTC#121759).

  - s390/bpf: Fix JMP_JGE_X (A > X) and JMP_JGT_X (A >= X)
    (bsc#917125, LTC#121759).

  - s390/bpf: Fix offset parameter for skb_copy_bits()
    (bsc#917125, LTC#121759).

  - s390/bpf: Fix sk_load_byte_msh() (bsc#917125,
    LTC#121759).

  - s390/bpf: Fix skb_copy_bits() parameter passing
    (bsc#917125, LTC#121759).

  - s390/bpf: Zero extend parameters before calling C
    function (bsc#917125, LTC#121759).

  - s390/sclp: Consolidate early sclp init calls to
    sclp_early_detect() (bsc#917125, LTC#122429).

  - s390/sclp: Determine HSA size dynamically for zfcpdump
    (bsc#917125, LTC#122429).

  - s390/sclp: Move declarations for sclp_sdias into
    separate header file (bsc#917125, LTC#122429).

  - s390/sclp: Move early code from sclp_cmd.c to
    sclp_early.c (bsc#917125, LTC#122429).

  - s390/sclp: replace uninitialized early_event_mask_sccb
    variable with sccb_early (bsc#917125, LTC#122429).

  - s390/sclp: revert smp-detect-possible-cpus.patch
    (bsc#917125, LTC#122429).

  - s390/sclp_early: Add function to detect sclp console
    capabilities (bsc#917125, LTC#122429).

  - s390/sclp_early: Get rid of
    sclp_early_read_info_sccb_valid (bsc#917125,
    LTC#122429).

  - s390/sclp_early: Pass sccb pointer to every *_detect()
    function (bsc#917125, LTC#122429).

  - s390/sclp_early: Replace early_read_info_sccb with
    sccb_early (bsc#917125, LTC#122429).

  - s390/sclp_early: Return correct HSA block count also for
    zero (bsc#917125, LTC#122429).

  - s390/smp: limit number of cpus in possible cpu mask
    (bsc#917125, LTC#122429).

  - s390: kgr, change the kgraft state only if enabled.

  - sched, time: Fix lock inversion in
    thread_group_cputime()

  - sched: Fix potential near-infinite
    distribute_cfs_runtime() loop (bsc#930786)

  - sched: Robustify topology setup (bsc#924809).

  - seqlock: Add irqsave variant of read_seqbegin_or_lock()
    (Time scalability).

  - storvsc: Set the SRB flags correctly when no data
    transfer is needed (bsc#931130).

  - x86/apic/uv: Update the APIC UV OEM check (bsc#929145).

  - x86/apic/uv: Update the UV APIC HUB check (bsc#929145).

  - x86/apic/uv: Update the UV APIC driver check
    (bsc#929145).

  - x86/microcode/intel: Guard against stack overflow in the
    loader (bsc#922944).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/899192"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/900881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/909312"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/913232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916225"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917125"
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
    value:"https://bugzilla.suse.com/920262"
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
    value:"https://bugzilla.suse.com/922734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927116"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927257"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927455"
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
    value:"https://bugzilla.suse.com/928135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928141"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929145"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929525"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930226"
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
    value:"https://bugzilla.suse.com/931014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3647.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-1465.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-2666.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-3332.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3339.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3636.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151071-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea406797"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-269=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-269=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-269=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2015-269=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2015-269=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-269=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/17");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.43-52.6.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.43-52.6.1")) flag++;


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
