#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:0168-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(88006);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/27 20:14:34 $");

  script_cve_id("CVE-2015-7550", "CVE-2015-8539", "CVE-2015-8543", "CVE-2015-8550", "CVE-2015-8551", "CVE-2015-8552", "CVE-2015-8569", "CVE-2015-8575");
  script_osvdb_id(131666, 131683, 131685, 131951, 131952, 132029, 132030, 132031);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : kernel (SUSE-SU-2016:0168-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 12 kernel was updated to receive various
security and bugfixes.

Following security bugs were fixed :

  - CVE-2015-7550: A local user could have triggered a race
    between read and revoke in keyctl (bnc#958951).

  - CVE-2015-8539: A negatively instantiated user key could
    have been used by a local user to leverage privileges
    (bnc#958463).

  - CVE-2015-8543: The networking implementation in the
    Linux kernel did not validate protocol identifiers for
    certain protocol families, which allowed local users to
    cause a denial of service (NULL function pointer
    dereference and system crash) or possibly gain
    privileges by leveraging CLONE_NEWUSER support to
    execute a crafted SOCK_RAW application (bnc#958886).

  - CVE-2015-8550: Compiler optimizations in the XEN PV
    backend drivers could have lead to double fetch
    vulnerabilities, causing denial of service or arbitrary
    code execution (depending on the configuration)
    (bsc#957988).

  - CVE-2015-8551, CVE-2015-8552: xen/pciback: For
    XEN_PCI_OP_disable_msi[|x] only disable if device has
    MSI(X) enabled (bsc#957990).

  - CVE-2015-8569: The (1) pptp_bind and (2) pptp_connect
    functions in drivers/net/ppp/pptp.c in the Linux kernel
    did not verify an address length, which allowed local
    users to obtain sensitive information from kernel memory
    and bypass the KASLR protection mechanism via a crafted
    application (bnc#959190).

  - CVE-2015-8575: Validate socket address length in
    sco_sock_bind() to prevent information leak
    (bsc#959399).

The following non-security bugs were fixed :

  - ACPICA: Correctly cleanup after a ACPI table load
    failure (bnc#937261).

  - ALSA: hda - Fix noise problems on Thinkpad T440s
    (boo#958504).

  - Input: aiptek - fix crash on detecting device without
    endpoints (bnc#956708).

  - Re-add copy_page_vector_to_user()

  - Refresh patches.xen/xen3-patch-3.12.46-47 (bsc#959705).

  - Refresh patches.xen/xen3-patch-3.9 (bsc#951155).

  - Update
    patches.suse/btrfs-8361-Btrfs-keep-dropped-roots-in-cach
    e-until-transaction

    -.patch (bnc#935087, bnc#945649, bnc#951615).

  - bcache: Add btree_insert_node() (bnc#951638).

  - bcache: Add explicit keylist arg to btree_insert()
    (bnc#951638).

  - bcache: Clean up keylist code (bnc#951638).

  - bcache: Convert btree_insert_check_key() to
    btree_insert_node() (bnc#951638).

  - bcache: Convert bucket_wait to wait_queue_head_t
    (bnc#951638).

  - bcache: Convert try_wait to wait_queue_head_t
    (bnc#951638).

  - bcache: Explicitly track btree node's parent
    (bnc#951638).

  - bcache: Fix a bug when detaching (bsc#951638).

  - bcache: Fix a lockdep splat in an error path
    (bnc#951638).

  - bcache: Fix a shutdown bug (bsc#951638).

  - bcache: Fix more early shutdown bugs (bsc#951638).

  - bcache: Fix sysfs splat on shutdown with flash only devs
    (bsc#951638).

  - bcache: Insert multiple keys at a time (bnc#951638).

  - bcache: Refactor journalling flow control (bnc#951638).

  - bcache: Refactor request_write() (bnc#951638).

  - bcache: Use blkdev_issue_discard() (bnc#951638).

  - bcache: backing device set to clean after finishing
    detach (bsc#951638).

  - bcache: kill closure locking usage (bnc#951638).

  - blktap: also call blkif_disconnect() when frontend
    switched to closed (bsc#952976).

  - blktap: refine mm tracking (bsc#952976).

  - block: Always check queue limits for cloned requests
    (bsc#902606).

  - btrfs: Add qgroup tracing (bnc#935087, bnc#945649).

  - btrfs: Adjust commit-transaction condition to avoid
    NO_SPACE more (bsc#958647).

  - btrfs: Fix out-of-space bug (bsc#958647).

  - btrfs: Fix tail space processing in
    find_free_dev_extent() (bsc#958647).

  - btrfs: Set relative data on clear
    btrfs_block_group_cache->pinned (bsc#958647).

  - btrfs: Update btrfs qgroup status item when rescan is
    done (bnc#960300).

  - btrfs: backref: Add special time_seq == (u64)-1 case for
    btrfs_find_all_roots() (bnc#935087, bnc#945649).

  - btrfs: backref: Do not merge refs which are not for same
    block (bnc#935087, bnc#945649).

  - btrfs: cleanup: remove no-used alloc_chunk in
    btrfs_check_data_free_space() (bsc#958647).

  - btrfs: delayed-ref: Cleanup the unneeded functions
    (bnc#935087, bnc#945649).

  - btrfs: delayed-ref: Use list to replace the ref_root in
    ref_head (bnc#935087, bnc#945649).

  - btrfs: extent-tree: Use ref_node to replace unneeded
    parameters in __inc_extent_ref() and __free_extent()
    (bnc#935087, bnc#945649).

  - btrfs: fix comp_oper to get right order (bnc#935087,
    bnc#945649).

  - btrfs: fix condition of commit transaction (bsc#958647).

  - btrfs: fix leak in qgroup_subtree_accounting() error
    path (bnc#935087, bnc#945649).

  - btrfs: fix order by which delayed references are run
    (bnc#949440).

  - btrfs: fix qgroup sanity tests (bnc#951615).

  - btrfs: fix race waiting for qgroup rescan worker
    (bnc#960300).

  - btrfs: fix regression running delayed references when
    using qgroups (bnc#951615).

  - btrfs: fix regression when running delayed references
    (bnc#951615).

  - btrfs: fix sleeping inside atomic context in qgroup
    rescan worker (bnc#960300).

  - btrfs: fix the number of transaction units needed to
    remove a block group (bsc#958647).

  - btrfs: keep dropped roots in cache until transaction
    commit (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add function qgroup_update_counters()
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add function qgroup_update_refcnt()
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add new function to record old_roots
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add new qgroup calculation function
    btrfs_qgroup_account_extents() (bnc#935087, bnc#945649).

  - btrfs: qgroup: Add the ability to skip given qgroup for
    old/new_roots (bnc#935087, bnc#945649).

  - btrfs: qgroup: Cleanup open-coded old/new_refcnt update
    and read (bnc#935087, bnc#945649).

  - btrfs: qgroup: Cleanup the old ref_node-oriented
    mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: Do not copy extent buffer to do qgroup
    rescan (bnc#960300).

  - btrfs: qgroup: Fix a regression in qgroup reserved space
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Make snapshot accounting work with new
    extent-oriented qgroup (bnc#935087, bnc#945649).

  - btrfs: qgroup: Record possible quota-related extent for
    qgroup (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch rescan to new mechanism
    (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch self test to extent-oriented
    qgroup mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: Switch to new extent-oriented qgroup
    mechanism (bnc#935087, bnc#945649).

  - btrfs: qgroup: account shared subtree during snapshot
    delete (bnc#935087, bnc#945649).

  - btrfs: qgroup: clear STATUS_FLAG_ON in disabling quota
    (bnc#960300).

  - btrfs: qgroup: exit the rescan worker during umount
    (bnc#960300).

  - btrfs: qgroup: fix quota disable during rescan
    (bnc#960300).

  - btrfs: qgroup: move WARN_ON() to the correct location
    (bnc#935087, bnc#945649).

  - btrfs: remove transaction from send (bnc#935087,
    bnc#945649).

  - btrfs: ulist: Add ulist_del() function (bnc#935087,
    bnc#945649).

  - btrfs: use btrfs_get_fs_root in resolve_indirect_ref
    (bnc#935087, bnc#945649).

  - btrfs: use global reserve when deleting unused block
    group after ENOSPC (bsc#958647).

  - cache: Fix sysfs splat on shutdown with flash only devs
    (bsc#951638).

  - cpusets, isolcpus: exclude isolcpus from load balancing
    in cpusets (bsc#957395).

  - drm/i915: Fix SRC_COPY width on 830/845g (bsc#758040).

  - drm: Allocate new master object when client becomes
    master (bsc#956876, bsc#956801).

  - drm: Fix KABI of 'struct drm_file' (bsc#956876,
    bsc#956801).

  - e1000e: Do not read ICR in Other interrupt (bsc#924919).

  - e1000e: Do not write lsc to ics in msi-x mode
    (bsc#924919).

  - e1000e: Fix msi-x interrupt automask (bsc#924919).

  - e1000e: Remove unreachable code (bsc#924919).

  - genksyms: Handle string literals with spaces in
    reference files (bsc#958510).

  - ipv6: fix tunnel error handling (bsc#952579).

  - lpfc: Fix null ndlp dereference in target_reset_handler
    (bsc#951392).

  - mm/mempolicy.c: convert the shared_policy lock to a
    rwlock (bnc#959436).

  - mm: remove PG_waiters from PAGE_FLAGS_CHECK_AT_FREE
    (bnc#943959).

  - pm, hinernate: use put_page in release_swap_writer
    (bnc#943959).

  - sched, isolcpu: make cpu_isolated_map visible outside
    scheduler (bsc#957395).

  - udp: properly support MSG_PEEK with truncated buffers
    (bsc#951199 bsc#959364).

  - xhci: Workaround to get Intel xHCI reset working more
    reliably (bnc#957546).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/758040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924919"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/937261"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/951638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/952976"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/956876"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957395"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957546"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958504"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958647"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/958951"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959364"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/960300"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8543.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8552.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8569.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8575.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20160168-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9497c66b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2016-107=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2016-107=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-107=1

SUSE Linux Enterprise Module for Public Cloud 12 :

zypper in -t patch SUSE-SLE-Module-Public-Cloud-12-2016-107=1

SUSE Linux Enterprise Live Patching 12 :

zypper in -t patch SUSE-SLE-Live-Patching-12-2016-107=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2016-107=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/20");
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
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"kernel-default-man-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-base-debuginfo-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debuginfo-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-debugsource-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-default-devel-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"kernel-syms-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debuginfo-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-debugsource-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-devel-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-default-extra-debuginfo-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-syms-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-debugsource-3.12.51-52.34.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"kernel-xen-devel-3.12.51-52.34.1")) flag++;


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
