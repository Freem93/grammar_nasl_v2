#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1611-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86121);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/14 14:25:31 $");

  script_cve_id("CVE-2014-9728", "CVE-2014-9729", "CVE-2014-9730", "CVE-2014-9731", "CVE-2015-0777", "CVE-2015-1420", "CVE-2015-1805", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-4167", "CVE-2015-4700", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5707");
  script_bugtraq_id(72357, 73014, 73699, 73921, 74951, 74963, 74964, 75001, 75356, 75510);
  script_osvdb_id(117759, 119409, 119615, 120284, 120316, 122921, 122965, 122966, 122967, 122968, 123637, 123996, 125710);

  script_name(english:"SUSE SLED11 / SLES11 Security Update : kernel (SUSE-SU-2015:1611-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP3 kernel was updated to receive various
security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-5707: An integer overflow in the SCSI generic
    driver could be potentially used by local attackers to
    crash the kernel or execute code (bsc#940338).

  - CVE-2015-5364: A remote denial of service (hang) via UDP
    flood with incorrect package checksums was fixed.
    (bsc#936831).

  - CVE-2015-5366: A remote denial of service (unexpected
    error returns) via UDP flood with incorrect package
    checksums was fixed. (bsc#936831).

  - CVE-2015-1420: A race condition in the handle_to_path
    function in fs/fhandle.c in the Linux kernel allowed
    local users to bypass intended size restrictions and
    trigger read operations on additional memory locations
    by changing the handle_bytes value of a file handle
    during the execution of this function (bnc#915517).

  - CVE-2015-4700: A local user could have created a bad
    instruction in the JIT processed BPF code, leading to a
    kernel crash (bnc#935705).

  - CVE-2015-4167: The UDF filesystem in the Linux kernel
    was vulnerable to a crash which could occur while
    fetching inode information from a corrupted/malicious
    udf file system image. (bsc#933907).

  - CVE-2014-9728 CVE-2014-9729 CVE-2014-9730 CVE-2014-9731:
    Various issues in handling UDF filesystems in the Linux
    kernel allowed the corruption of kernel memory and other
    issues. An attacker able to mount a corrupted/malicious
    UDF file system image could cause the kernel to crash.
    (bsc#933904 bsc#933896)

  - CVE-2015-2150: The Linux kernel did not properly
    restrict access to PCI command registers, which might
    have allowed local guest users to cause a denial of
    service (non-maskable interrupt and host crash) by
    disabling the (1) memory or (2) I/O decoding for a PCI
    Express device and then accessing the device, which
    triggers an Unsupported Request (UR) response
    (bsc#919463).

  - CVE-2015-0777: drivers/xen/usbback/usbback.c as used in
    the Linux kernel 2.6.x and 3.x in SUSE Linux
    distributions, allowed guest OS users to obtain
    sensitive information from uninitialized locations in
    host OS kernel memory via unspecified vectors
    (bnc#917830).

  - CVE-2015-2830: arch/x86/kernel/entry_64.S in the Linux
    kernel did not prevent the TS_COMPAT flag from reaching
    a user-mode task, which might have allowed local users
    to bypass the seccomp or audit protection mechanism via
    a crafted application that uses the (1) fork or (2)
    close system call, as demonstrated by an attack against
    seccomp before 3.16 (bnc#926240).

  - CVE-2015-1805: The Linux kernels implementation of
    vectored pipe read and write functionality did not take
    into account the I/O vectors that were already processed
    when retrying after a failed atomic access operation,
    potentially resulting in memory corruption due to an I/O
    vector array overrun. A local, unprivileged user could
    use this flaw to crash the system or, potentially,
    escalate their privileges on the system. (bsc#933429).

Also the following non-security bugs were fixed :

  - audit: keep inode pinned (bsc#851068).

  - btrfs: be aware of btree inode write errors to avoid fs
    corruption (bnc#942350).

  - btrfs: check if previous transaction aborted to avoid fs
    corruption (bnc#942350).

  - btrfs: deal with convert_extent_bit errors to avoid fs
    corruption (bnc#942350).

  - cifs: Fix missing crypto allocation (bnc#937402).

  - client MUST ignore EncryptionKeyLength if
    CAP_EXTENDED_SECURITY is set (bnc#932348).

  - drm: ast,cirrus,mgag200: use drm_can_sleep (bnc#883380,
    bsc#935572).

  - drm/cirrus: do not attempt to acquire a reservation
    while in an interrupt handler (bsc#935572).

  - drm/mgag200: do not attempt to acquire a reservation
    while in an interrupt handler (bsc#935572).

  - drm/mgag200: Do not do full cleanup if
    mgag200_device_init fails.

  - ext3: Fix data corruption in inodes with journalled data
    (bsc#936637)

  - ext4: handle SEEK_HOLE/SEEK_DATA generically
    (bsc#934944).

  - fanotify: Fix deadlock with permission events
    (bsc#935053).

  - fork: reset mm->pinned_vm (bnc#937855).

  - hrtimer: prevent timer interrupt DoS (bnc#886785).

  - hugetlb: do not account hugetlb pages as NR_FILE_PAGES
    (bnc#930092).

  - hugetlb, kabi: do not account hugetlb pages as
    NR_FILE_PAGES (bnc#930092).

  - IB/core: Fix mismatch between locked and pinned pages
    (bnc#937855).

  - iommu/amd: Fix memory leak in free_pagetable
    (bsc#935866).

  - iommu/amd: Handle integer overflow in dma_ops_area_alloc
    (bsc#931538).

  - iommu/amd: Handle large pages correctly in
    free_pagetable (bsc#935866).

  - ipr: Increase default adapter init stage change timeout
    (bsc#930761).

  - ixgbe: Use pci_vfs_assigned instead of
    ixgbe_vfs_are_assigned (bsc#927355).

  - kdump: fix crash_kexec()/smp_send_stop() race in panic()
    (bnc#937444).

  - kernel: add panic_on_warn. (bsc#934742)

  - kvm: irqchip: Break up high order allocations of
    kvm_irq_routing_table (bnc#926953).

  - libata: prevent HSM state change race between ISR and
    PIO (bsc#923245).

  - md: use kzalloc() when bitmap is disabled (bsc#939994).

  - megaraid_sas: Use correct reset sequence in adp_reset()
    (bsc#894936).

  - mlx4: Check for assigned VFs before disabling SR-IOV
    (bsc#927355).

  - mm/hugetlb: check for pte NULL pointer in
    __page_check_address() (bnc#929143).

  - mm: restrict access to slab files under procfs and sysfs
    (bnc#936077).

  - net: fib6: fib6_commit_metrics: fix potential NULL
    pointer dereference (bsc#867362).

  - net: Fix 'ip rule delete table 256' (bsc#873385).

  - net: ipv6: fib: do not sleep inside atomic lock
    (bsc#867362).

  - net/mlx4_core: Do not disable SRIOV if there are active
    VFs (bsc#927355).

  - nfsd: Fix nfsv4 opcode decoding error (bsc#935906).

  - nfsd: support disabling 64bit dir cookies (bnc#937503).

  - nfs: never queue requests with rq_cong set on the
    sending queue (bsc#932458).

  - nfsv4: Minor cleanups for nfs4_handle_exception and
    nfs4_async_handle_error (bsc#939910).

  - pagecache limit: add tracepoints (bnc#924701).

  - pagecache limit: Do not skip over small zones that
    easily (bnc#925881).

  - pagecache limit: export debugging counters via
    /proc/vmstat (bnc#924701).

  - pagecache limit: fix wrong nr_reclaimed count
    (bnc#924701).

  - pagecache limit: reduce starvation due to reclaim
    retries (bnc#925903).

  - pci: Add SRIOV helper function to determine if VFs are
    assigned to guest (bsc#927355).

  - pci: Disable Bus Master only on kexec reboot
    (bsc#920110).

  - pci: disable Bus Master on PCI device shutdown
    (bsc#920110).

  - pci: Disable Bus Master unconditionally in
    pci_device_shutdown() (bsc#920110).

  - pci: Don't try to disable Bus Master on disconnected PCI
    devices (bsc#920110).

  - perf, nmi: Fix unknown NMI warning (bsc#929142).

  - perf/x86/intel: Move NMI clearing to end of PMI handler
    (bsc#929142).

  - rtlwifi: rtl8192cu: Fix kernel deadlock (bnc#927786).

  - sched: fix __sched_setscheduler() vs load balancing race
    (bnc#921430)

  - scsi_error: add missing case statements in
    scsi_decide_disposition() (bsc#920733).

  - scsi: Set hostbyte status in scsi_check_sense()
    (bsc#920733).

  - scsi: set host msg status correctly (bnc#933936)

  - scsi: vmw_pvscsi: Fix pvscsi_abort() function
    (bnc#940398 bsc#930934).

  - st: NULL pointer dereference panic caused by use after
    kref_put by st_open (bsc#936875).

  - udf: Remove repeated loads blocksize (bsc#933907).

  - usb: core: Fix USB 3.0 devices lost in NOTATTACHED state
    after a hub port reset (bnc#937641).

  - vmxnet3: Bump up driver version number (bsc#936423).

  - vmxnet3: Changes for vmxnet3 adapter version 2 (fwd)
    (bug#936423).

  - vmxnet3: Fix memory leaks in rx path (fwd) (bug#936423).

  - vmxnet3: Register shutdown handler for device (fwd)
    (bug#936423).

  - x86/mm: Improve AMD Bulldozer ASLR workaround
    (bsc#937032).

  - x86, tls: Interpret an all-zero struct user_desc as 'no
    segment' (bsc#920250).

  - x86, tls, ldt: Stop checking lm in LDT_empty
    (bsc#920250).

  - xenbus: add proper handling of XS_ERROR from Xenbus for
    transactions.

  - xfs: avoid mounting of xfs filesystems with inconsistent
    option (bnc#925705)

  - zcrypt: Fixed reset and interrupt handling of AP queues
    (bnc#936925, LTC#126491).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/851068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/867362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/873385"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/883380"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/886785"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/894936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915517"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920110"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925903"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/926953"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/927786"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929142"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/929143"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930761"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/930934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933936"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/934944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935866"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935906"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936875"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937503"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/939994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/940398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942350"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9728.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9731.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1420.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1805.html"
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
    value:"https://www.suse.com/security/cve/CVE-2015-4167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4700.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5364.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5366.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5707.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151611-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?441d7fc3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-kernel-201508-12100=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-kernel-201508-12100=1

SUSE Linux Enterprise Server 11-EXTRA :

zypper in -t patch slexsp3-kernel-201508-12100=1

SUSE Linux Enterprise Desktop 11-SP3 :

zypper in -t patch sledsp3-kernel-201508-12100=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-kernel-201508-12100=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-bigsmp-extra");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/24");
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
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-ec2-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"s390x", reference:"kernel-default-man-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-source-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-syms-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-trace-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"kernel-default-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-ec2-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-default-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-source-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-syms-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-trace-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-bigsmp-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"x86_64", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-default-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-source-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-syms-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-trace-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-xen-extra-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-base-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-devel-3.0.101-0.47.67.2")) flag++;
if (rpm_check(release:"SLED11", sp:"3", cpu:"i586", reference:"kernel-pae-extra-3.0.101-0.47.67.2")) flag++;


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
