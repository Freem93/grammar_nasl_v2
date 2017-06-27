#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59521);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/06/15 15:57:03 $");

  script_cve_id("CVE-2011-2928", "CVE-2011-4077", "CVE-2011-4324", "CVE-2011-4330", "CVE-2012-2313", "CVE-2012-2319");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 8161)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This Linux kernel update fixes various security issues and bugs in the
SUSE Linux Enterprise 10 SP4 kernel.

The following security issues have been fixed :

  - A memory corruption when mounting a hfsplus filesystem
    was fixed that could be used by local attackers able to
    mount filesystem to crash the system. (CVE-2012-2319)

  - The dl2k network card driver lacked permission handling
    for some ethtool ioctls, which could allow local
    attackers to start/stop the network card.
    (CVE-2012-2313)

  - The befs_follow_linkl function in fs/befs/linuxvfs.c in
    the Linux kernel did not validate the lenght attribute
    of long symlinsk, which allowed local users to cause a
    denial of service (incorrect pointer dereference and
    Ooops) by accessing a long symlink on a malformed Be
    filesystem. (CVE-2011-2928)

  - Fixed a memory corruption possibility in xfs readlink,
    which could be used by local attackers to crash the
    system or potentially execute code by mounting a
    prepared xfs filesystem image. (CVE-2011-4077)

  - A BUG() error report in the nfs4xdr routines on a NFSv4
    mount was fixed that could happen during mknod.
    (CVE-2011-4324)

  - Mounting a corrupted hfs filesystem could lead to a
    buffer overflow. (CVE-2011-4330)

The following non-security issues have been fixed :

  - kernel: pfault task state race (bnc#764128,LTC#81724).

  - ap: Toleration for ap bus devices with device type 10.
    (bnc#761389)

  - hugetlb, numa: fix interleave mpol reference count.
    (bnc#762111)

  - cciss: fixup kdump. (bnc#730200)

  - kdump: Avoid allocating bootmem map over crash reserved
    region. (bnc#749168, bnc#722400, bnc#742881)

  - qeth: Improve OSA Express 4 blkt defaults
    (bnc#754964,LTC#80325).

  - zcrypt: Fix parameter checking for ZSECSENDCPRB ioctl
    (bnc#754964,LTC#80378).

  - virtio: add names to virtqueue struct, mapping from
    devices to queues. (bnc#742148)

  - virtio: find_vqs/del_vqs virtio operations. (bnc#742148)

  - virtio_pci: optional MSI-X support. (bnc#742148)

  - virtio_pci: split up vp_interrupt. (bnc#742148)

  - knfsd: nfsd4: fix laundromat shutdown race (752556).

  - driver core: Check for valid device in
    bus_find_device(). (bnc#729685)

  - VMware detection backport from mainline. (bnc#671124,
    bnc#747381)

  - net: adding memory barrier to the poll and receive
    callbacks. (bnc#746397 / bnc#750928)

  - qla2xxx: drop reference before wait for completion.
    (bnc#744592)

  - qla2xxx: drop reference before wait for completion.
    (bnc#744592)

  - ixgbe driver sets all WOL flags upon initialization so
    that machine is powered on as soon at it is switched
    off. (bnc#693639)

  - Properly release MSI(X) vector(s) when MSI(X) gets
    disabled. (bnc#723294, bnc#721869)

  - scsi: Always retry internal target error. (bnc#745640)

  - cxgb4: fix parent device access in netdev_printk.
    (bnc#733155)

  - lcs: lcs offline failure (bnc#752486,LTC#79788).

  - qeth: add missing wake_up call (bnc#752486,LTC#79899).

  - NFSD: Fill in WCC data for REMOVE, RMDIR, MKNOD, and
    MKDIR. (bnc#751880)

  - xenbus: Reject replies with payload >
    XENSTORE_PAYLOAD_MAX.

  - xenbus_dev: add missing error checks to watch handling.

  - blkfront: properly fail packet requests. (bnc#745929)

  - blkback: failure to write 'feature-barrier' node is
    non-fatal.

  - igb: Free MSI and MSIX interrupt vectors on driver
    remove or shutdown. (bnc#723294)

  - igb: Fix for Alt MAC Address feature on 82580 and later
    devices. (bnc#746980)

  - igb: Free MSI and MSIX interrupt vectors on driver
    remove or shutdown. (bnc#723294)

  - cfq: Fix infinite loop in cfq_preempt_queue().
    (bnc#724692)

  - dasd: fix fixpoint divide exception in define_extent
    (bnc#750168,LTC#79125).

  - ctcmpc: use correct idal word list for ctcmpc
    (bnc#750168,LTC#79264).

  - patches.fixes/ext3-fix-reuse-of-freed-blocks.diff:
    Delete. Patch should not really be needed and apparently
    causes a performance regression. (bnc#683270)

  - tcp: fix race condition leading to premature termination
    of sockets in FIN_WAIT2 state and connection being
    reset. (bnc#745760)

  - kernel: console interrupts vs. panic
    (bnc#737325,LTC#77272).

  - af_iucv: remove IUCV-pathes completely
    (bnc#737325,LTC#78292).

  - qdio: wrong buffers-used counter for ERROR buffers
    (bnc#737325,LTC#78758).

  - ext3: Fix credit estimate for DIO allocation.
    (bnc#745732)

  - jbd: validate sb->s_first in journal_get_superblock().
    (bnc#730118)

  - ocfs2: serialize unaligned aio. (bnc#671479)

  - cifs: eliminate usage of kthread_stop for cifsd.
    (bnc#718343)

  - virtio: fix wrong type used, resulting in truncated
    addresses in bigsmp kernel. (bnc#737899)

  - cciss: Adds simple mode functionality. (bnc#730200)

  - blktap: fix locking (again). (bnc#724734)

  - block: Initial support for data-less (or empty) barrier
    support (bnc#734707 FATE#313126).

  - xen: Do not allow empty barriers to be passed down to
    queues that do not grok them (bnc#734707 FATE#313126).

  - linkwatch: Handle jiffies wrap-around. (bnc#740131)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2928.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4324.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4330.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2313.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-2319.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 8161.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.97.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.97.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
