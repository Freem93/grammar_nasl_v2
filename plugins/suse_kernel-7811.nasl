#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(59160);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/05/29 10:54:40 $");

  script_cve_id("CVE-2009-4067", "CVE-2011-1577", "CVE-2011-1776", "CVE-2011-3191", "CVE-2011-3363");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 7811)");
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

  - A USB string descriptor overflow in the auerwald USB
    driver was fixed, which could be used by physically
    proximate attackers to cause a kernel crash.
    (CVE-2009-4067)

  - Always check the path in CIFS mounts to avoid
    interesting filesystem path interaction issues and
    potential crashes. (CVE-2011-3363)

  - A malicious CIFS server could cause a integer overflow
    on the local machine on directory index operations, in
    turn causing memory corruption. (CVE-2011-3191)

  - The is_gpt_valid function in fs/partitions/efi.c in the
    Linux kernel did not check the size of an Extensible
    Firmware Interface (EFI) GUID Partition Table (GPT)
    entry, which allowed physically proximate attackers to
    cause a denial of service (heap-based buffer overflow
    and OOPS) or obtain sensitive information from kernel
    heap memory by connecting a crafted GPT storage device,
    a different vulnerability than CVE-2011-1577.
    (CVE-2011-1776)

The following non-security issues have been fixed :

  - md: fix deadlock in md/raid1 and md/raid10 when handling
    a read error. (bnc#628343)

  - md: fix possible raid1/raid10 deadlock on read error
    during resync. (bnc#628343)

  - Add timeo parameter to /proc/mounts for nfs filesystems.
    (bnc#616256)

  - virtio: indirect ring entries
    (VIRTIO_RING_F_INDIRECT_DESC). (bnc#713876)

  - virtio: teach virtio_has_feature() about transport
    features. (bnc#713876)

  - nf_nat: do not add NAT extension for confirmed
    conntracks. (bnc#709213)

  - 8250: Oxford Semiconductor Devices. (bnc#717126)

  - 8250_pci: Add support for the Digi/IBM PCIe 2-port
    Adapter. (bnc#717126)

  - 8250: Fix capabilities when changing the port type.
    (bnc#717126)

  - 8250: Add EEH support. (bnc#717126)

  - xfs: fix memory reclaim recursion deadlock on locked
    inode buffer. (bnc#699355 / bnc#699354 / bnc#721830)

  - ipmi: do not grab locks in run-to-completion mode.
    (bnc#717421)

  - cifs: add fallback in is_path_accessible for old
    servers. (bnc#718028)

  - cciss: do not attempt to read from a write-only
    register. (bnc#683101)

  - s390: kernel: System hang if hangcheck timer expires
    (bnc#712009,LTC#74157).

  - s390: kernel: NSS creation with initrd fails
    (bnc#712009,LTC#74207).

  - s390: kernel: remove code to handle topology interrupts
    (bnc#712009,LTC#74440).

  - xen: Added 1083-kbdfront-absolute-coordinates.patch.
    (bnc#717585)

  - acpi: Use a spinlock instead of mutex to guard gbl_lock
    access. (bnc#707439)

  - Allow balance_dirty_pages to help other filesystems.
    (bnc#709369)

  - nfs: fix congestion control. (bnc#709369)

  - NFS: Separate metadata and page cache revalidation
    mechanisms. (bnc#709369)

  - jbd: Fix oops in journal_remove_journal_head().
    (bnc#694315)

  - xen/blkfront: avoid NULL de-reference in CDROM ioctl
    handling. (bnc#701355)

  - xen/x86: replace order-based range checking of M2P table
    by linear one.

  - xen/x86: use dynamically adjusted upper bound for
    contiguous regions. (bnc#635880)

  - Fix type in
    patches.fixes/libiscsi-dont-run-scsi-eh-if-iscsi-task-is
    -making-progress.

  - s390: cio: Add timeouts for internal IO
    (bnc#701550,LTC#72691).

  - s390: kernel: first time swap use results in heavy
    swapping (bnc#701550,LTC#73132).

  - s390: qeth: wrong number of output queues for
    HiperSockets (bnc#701550,LTC#73814)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-4067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-1776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3191.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3363.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 7811.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
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
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.91.1")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.91.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
