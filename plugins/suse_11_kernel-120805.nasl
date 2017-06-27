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
  script_id(64178);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:46:55 $");

  script_cve_id("CVE-2012-3375", "CVE-2012-3400");

  script_name(english:"SuSE 11.2 Security Update : Linux kernel (SAT Patch Numbers 6641 / 6643 / 6648)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 11 SP2 kernel was updated to 3.0.38, fixing
various bugs and security issues.

The following security issues have been fixed :

  - Several buffer overread and overwrite errors in the UDF
    logical volume descriptor code have been fixed that
    might have have allowed local attackers able to mount
    UDF volumes to crash the kernel or potentially gain
    privileges. (CVE-2012-3400)

  - A denial of service (crash) in epoll has been fixed. The
    three NTP leapsecond issues were fixed and are contained
    in Linux Kernel stable 3.0.38. (CVE-2012-3375)

The Libceph/ceph/rbd framework was imported for later Cloud storage
usage.

Various bug and security fixes were integrated from the Linux stable
kernel 3.0.34-3.0.38 upgrade and are not explicitly listed here.

The following other non-security issues have been fixed :

S/390

  - dasd: Use correct queue for aborting requests.

  - dasd: Abort requests from correct queue.

  - [S390] Do not clobber personality flags on exec.
    (bnc#770034)

  - dasd: Kick tasklet instead of processing the
    request_queue directly.

  - s390/kernel: CPU idle vs CPU hotplug
    (bnc#772407,LTC#83468).

  - lgr: Make lgr_page static (bnc#772407,LTC#83520).

  - s390/kernel: incorrect task size after fork of a 31 bit
    process (bnc#772407,LTC#83674).

  - dasd: Abort all requests on the request_queue, too.
    (bnc#768084)

  - DASD: Add timeout attribute. (bnc#771361)

  - dasd: Fixup typo in debugging message.

  - patches.suse/dasd-fail-all-requests-after-timeout.patch:
    Fixup handling of failfast requests. (bnc#768084)

  - s390: allow zcrypt to /dev/random feeding to be resumed.
    (bnc#718910)

  - s390/hypfs: Missing files and directories
    (bnc#769407,LTC#82838).

  - dasd: Fail all requests after timeout. (bnc#768084)

  - s390/kernel: Add z/VM LGR detection
    (bnc#767281,LTC#RAS1203). BTRFS fixes (3.3-3.5+)

  - Btrfs: avoid sleeping in verify_parent_transid while
    atomic

  - Btrfs: fix btrfs_release_extent_buffer_page with the
    right usage of num_extent_pages

  - Btrfs: do not check delalloc when updating disk_i_size

  - Btrfs: look into the extent during find_all_leafs

  - Btrfs: do not set for_cow parameter for tree block
    functions

  - Btrfs: fix defrag regression

  - Btrfs: fix missing inherited flag in rename

  - Btrfs: do not resize a seeding device

  - Btrfs: cast devid to unsigned long long for printk %llu

  - Btrfs: add a missing spin_lock

  - Btrfs: restore restriper state on all mounts

  - Btrfs: resume balance on rw (re)mounts properly

  - Btrfs: fix tree log remove space corner case

  - Btrfs: hold a ref on the inode during writepages

  - Btrfs: do not return EINVAL instead of ENOMEM from
    open_ctree()

  - Btrfs: do not ignore errors from
    btrfs_cleanup_fs_roots() when mounting

  - Btrfs: fix error handling in __add_reloc_root()

  - Btrfs: return error of btrfs_update_inode() to caller

  - Btrfs: fix typo in cow_file_range_async and
    async_cow_submit

  - Btrfs: fix btrfs_is_free_space_inode to recognize btree
    inode

  - Btrfs: kill root from btrfs_is_free_space_inode

  - Btrfs: zero unused bytes in inode item

  - disable
    patches.suse/btrfs-8052-fix-wrong-information-of-the-dir
    ectory-in-the-.patch. (bnc#757059)

XEN

  - Refresh Xen patches (bnc#772831, add spinlock.nopoll
    option).

  - Update Xen patches to 3.0.35.

  - xen/thp: avoid atomic64_read in pmd_read_atomic for
    32bit PAE. (bnc#762991)

  - Update Xen config files
    (CONFIG_XEN_SPINLOCK_ACQUIRE_NESTING=1). MD

  - md: Do not truncate size at 4TB for RAID0 and Linear

  - md/bitmap: Do not write bitmap while earlier writes
    might be in-fligh. (bnc#771398)

  - md: Fixup blktrace information.

  - md: Abort pending request for RAID10. (bnc#773251)

  - md: add raid10 tracepoints. (bnc#768084)

  - md: wakeup thread upon rdev_dec_pending(). (bnc#771398)

  - md: Correctly register error code on failure.

  - md: Do not take mddev lock when reading rdev attributes
    from sysfs. (bnc#772420)

  - md: unblock SET_DISK_FAULTY ioctl (bnc#768084). Hyper-V

  - net/hyperv: Use wait_event on outstanding sends during
    device removal.

  - Tools: hv: verify origin of netlink connector message.

  - hyperv: Add support for setting MAC from within guests.

  - Drivers: hv: Change the hex constant to a decimal
    constant.

  - hyperv: Add error handling to rndis_filter_device_add().

  - hyperv: Add a check for ring_size value.

  - Drivers: hv: Cleanup the guest ID computation.

  - hv: add RNDIS_OID_GEN_RNDIS_CONFIG_PARAMETER. Scheduler

  - sched: Make sure to not re-read variables after
    validation. (bnc#769685)

  - sched: Only queue remote wakeups when crossing cache
    boundaries part2. (bnc#754690)

  - sched: really revert latency defaults to SP1 values.
    (bnc#754690)

  - sched: optimize latency defaults. (bnc#754690)

  - sched: Save some hrtick_start_fair cycles. (bnc#754690)

  - sched: use rt.nr_cpus_allowed to recover
    select_task_rq() cycles. (bnc#754690)

  - sched: Set skip_clock_update in yield_task_fair().
    (bnc#754690)

  - sched: Do not call task_group() too many times in
    set_task_rq(). (bnc#754690)

  - sched: ratelimit nohz. (bnc#754690)

  - sched: Wrap scheduler p->cpus_allowed access.
    (bnc#754690)

  - sched: Avoid SMT siblings in select_idle_sibling() if
    possible. (bnc#754690)

  - sched: Clean up domain traversal in
    select_idle_sibling(). (bnc#754690)

  - sched: Remove rcu_read_lock/unlock() from
    select_idle_sibling(). (bnc#754690)

  - sched: Fix the sched group node allocation for
    SD_OVERLAP domains. (bnc#754690)

  - sched: add SD_SHARE_PKG_RESOURCES domain flags proc
    handler. (bnc#754690)

  - sched: fix select_idle_sibling() induced bouncing
    (bnc#754690). Other fixes

  - rt2800: add chipset revision RT5390R support.
    (bnc#772566)

  - reiserfs: fix deadlocks with quotas. (bnc#774285)

  - VFS: avoid prepend_path warning about d_obtain_alias
    aliases. (bnc#773006)

  - ntp: avoid printk under xtime_lock. (bnc#767684)

  - kvm: kvmclock: apply kvmclock offset to guest wall clock
    time. (bnc#766445)

  - bonding: allow all slave speeds. (bnc#771428)

  - mm: hugetlbfs: Close race during teardown of hugetlbfs
    shared page tables.

  - mm: hugetlbfs: Correctly detect if page tables have just
    been shared.

  -
    patches.fixes/mm-hugetlb-decrement-mapcount-under-page_t
    able_lock.patch: Delete. (Fix bad PMD message displayed
    while using hugetlbfs (bnc#762366)).

  - ALSA: hda - Evaluate gpio_led hints at the right moment.
    (bnc#773878)

  - proc: stats: Use arch_idle_time for idle and iowait
    times if available. (bnc#772893)

  - tcp: perform DMA to userspace only if there is a task
    waiting for it. (bnc#773606)

  - rt2x00: fix rt3290 resuming failed. (bnc#771778)

  - patches.suse/SUSE-bootsplash: Refresh. (Fix wrong
    vfree() (bnc#773406))

  - vhost: do not forget to schedule(). (bnc#767983)

  - powerpc, kabi: reintroduce __cputime_msec_factor.
    (bnc#771242)

  - powerpc: Fix wrong divisor in usecs_to_cputime.
    (bnc#771242)

  - mm: use cpu_chill() in spin_trylock_page() and cancel on
    immediately RT. (bnc#768470)

  - be2net: Fix EEH error reset before a flash dump
    completes. (bnc#755546)

  - st: Fix adding of tape link from device directory.
    (bnc#771102)

  - idr: Fix locking of minor idr during failure-case
    removal and add freeing of minor idr during device
    removal.

  - add firmware update for Atheros 0cf3:311f. (bnc#761775)

  - Unset CONFIG_WATCHDOG_NOWAYOUT to prevent reboot of
    openais on service stop. (bnc#756585)

  - Update config files: Enable CONFIG_RT2800PCI_RT3290.

  - ida: simplified functions for id allocation.
    (bnc#749291)

  - ida: make ida_simple_get/put() IRQ safe. (bnc#749291)

  - virtio-blk: use ida to allocate disk index. (bnc#749291)

  - USB: option: Add USB ID for Novatel Ovation MC551.
    (bnc#770269)

  - USB: option: add id for Cellient MEN-200. (bnc#770269)

  - Fix the position of SUSE logo on text screen.
    (bnc#770238)

  - enable Atheros 0cf3:311e for firmware upload.
    (bnc#766733)

  - scsi_dh_alua: Improve error handling. (bnc#715635)

  - scsi: remove an unhandled error code message.
    (bnc#715635)

  - Add to support Ralink ROMA wifi chip. (bnc#758703)

  - x86_64, UV: Update NMI handler for UV1000/2000 systems.
    (bnc#746509, bnc#744655)

  - kdb: Fix merge error in original kdb x86 patch.
    (bnc#746509)

  - udf: Avoid run away loop when partition table length is
    corrupted. (bnc#769784)

  - udf: Fortify loading of sparing table. (bnc#769784)

  - udf: Use ret instead of abusing i in
    udf_load_logicalvol(). (bnc#769784)

  - intel_ips: blacklist HP ProBook laptops. (bnc#720946)

  - drm: edid: Do not add inferred modes with higher
    resolution. (bnc#753172)

  - init: mm: Reschedule when initialising large numbers of
    memory sections. (bnc#755620).

  - x86/apic: Use x2apic physical mode based on FADT
    setting. (bnc#768052)

  - acpiphp: add dmi info to acpiphp module. (bnc#754391)

  - ntp: fix leap second hrtimer deadlock. (bnc#768632)

  - ntp: avoid printk under xtime_lock. (bnc#767684)

  - nohz: Fix update_ts_time_stat idle accounting.
    (bnc#767469, bnc#705551)

  - nohz: Make idle/iowait counter update conditional.
    (bnc#767469, bnc#705551)

  - bug: introduce BUILD_BUG_ON_INVALID() macro

  - bug: completely remove code generated by disabled. (VM
    Performance).

  - mm: call cond_resched in putback_lru_pages. (bnc#763968)

  - Update x84-64 Xen config file
    (CONFIG_ACPI_PROCESSOR_AGGREGATOR=m).

  - ia64 is odd man out, CONFIG_SCHED_HRTICK is not set, fix
    build failure due to missing hrtick_enabled() in that
    case.

  - drm: Add poll blacklist for Dell Latitude E5420.
    (bnc#756276)

  - supported.conf: mark libceph and rbd as unsupported.

  - drm/i915: Fix eDP blank screen after S3 resume on HP
    desktops. (bnc#752352)

  - mm: hugetlb: Decrement mapcount under page table lock
    (Consistent mapcount decrementing under lock
    (bnc#762366)).

  - mm: hugetlb: flush_tlb_range() needs page_table_lock
    when mmap_sem is not held (Consistent locking for TLB
    flush of hugetlb pages (bnc#762366)).

  - mm/hugetlb.c: undo change to page mapcount in fault
    handler (Handle potential leaks in hugetlbfs error paths
    (bnc#762366)).

  - drm/i915: Not all systems expose a firmware or platform
    mechanism for changing the backlight intensity on i915,
    so add native driver support. (bnc#752352)

  - i915: do not setup intel_backlight twice. (bnc#752352)

  - drm/i915: enable vdd when switching off the eDP panel.
    (bnc#752352)

  - Add missing definition blk_queue_dead().

  - Backport patches from mainline to fix SCSI crash under
    heavy load (bnc#738284) :

  - block: add blk_queue_dead(). (bnc#738284)

  - block: add missing blk_queue_dead() checks. (bnc#738284)

  - block: Fix race on request.end_io invocations.
    (bnc#738284)

  - fc class: fix scanning when devs are offline.
    (bnc#738284)

  - scsi: Fix device removal NULL pointer dereference.
    (bnc#738284)

  - fix DID_TARGET_FAILURE and DID_NEXUS_FAILURE host byte
    settings. (bnc#738284)

  - scsi: Stop accepting SCSI requests before removing a
    device. (bnc#738284)

  - Delete preliminary patch.

  - Provide obsoleted KMPs (bnc#753353), fix ath3k
    obsoletes.

  - mm: filemap: Optimise file-backed page faulting by
    emulating an adaptive sleeping spinlock. (bnc#762414)

  - Add yet another product ID for HP cert machines.
    (bnc#764339)

  - x86: check for valid irq_cfg pointer in
    smp_irq_move_cleanup_interrupt. (bnc#763754)

  - backing-dev: use synchronize_rcu_expedited instead of
    synchronize_rcu. (bnc#766027)

  - sysfs: count subdirectories. (bnc#766027)

  - kABI fix for sysfs-count-subdirectories. (bnc#766027)

  - block: Introduce blk_set_stacking_limits function.
    (bnc#763026)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=705551"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=715635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=718910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=720946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=738284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=746509"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=749291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=752352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=753353"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=754690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=755620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=756585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=757059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=758703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=761775"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763754"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=763968"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=764339"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=766733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=767983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768470"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=768632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769784"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=769896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770034"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=770269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771361"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772420"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772893"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773878"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3375.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3400.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 6641 / 6643 / 6648 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-default-extra-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-pae-extra-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-source-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-syms-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-trace-extra-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"kernel-xen-extra-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-default-extra-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-source-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-syms-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-trace-extra-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"kernel-xen-extra-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-default-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-source-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-syms-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"kernel-trace-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-ec2-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-pae-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"i586", reference:"kernel-xen-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"kernel-default-man-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-ec2-devel-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-base-3.0.38-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"kernel-xen-devel-3.0.38-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
