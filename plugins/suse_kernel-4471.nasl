#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(29488);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2012/05/17 11:12:38 $");

  script_cve_id("CVE-2007-4571", "CVE-2007-4573");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 4471)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

  - It was possible for local user to become root by
    exploiting a bug in the IA32 system call emulation. This
    affects x86_64 platforms with kernel 2.4.x and 2.6.x
    before 2.6.22.7 only. (CVE-2007-4573)

  - An information disclosure vulnerability in the ALSA
    driver can be exploited by local users to read sensitive
    data from the kernel memory. (CVE-2007-4571)

and the following non security bugs :

  - patches.xen/xen-blkback-cdrom: CDROM removable
    media-present attribute plus handling code [#159907]

  - patches.drivers/libata-add-pata_dma-kernel-parameter:
    libata: Add a drivers/ide style DMA disable [#229260]
    [#272786]

  - patches.drivers/libata-sata_via-kill-SATA_PATA_SHARING:
    sata_via: kill SATA_PATA_SHARING register handling
    [#254158] [#309069]

  - patches.drivers/libata-sata_via-add-PCI-IDs: sata_via:
    add PCI IDs [#254158] [#326647]

  - supported.conf: Marked 8250 and 8250_pci as supported
    (only Xen kernels build them as modules) [#260686]

  - patches.fixes/bridge-module-get-put.patch: Module use
    count must be updated as bridges are created/destroyed
    [#267651]

  - patches.fixes/iscsi-netware-fix: Linux Initiator hard
    hangs writing files to NetWare target [#286566]

  - patches.fixes/lockd-chroot-fix: Allow lockd to work
    reliably with applications in a chroot [#288376]
    [#305480]

  - add patches.fixes/x86_64-hangcheck_timer-fix.patch fix
    monotonic_clock() and hangcheck_timer [#291633]

  - patches.arch/sn_hwperf_cpuinfo_fix.diff: Correctly count
    CPU objects for SGI ia64/sn hwperf interface [#292240]

  - Extend reiserfs to properly support file systems up to
    16 TiB [#294754]

  - patches.fixes/reiserfs-signedness-fixes.diff: reiserfs:
    fix usage of signed ints for block numbers

  - patches.fixes/reiserfs-fix-large-fs.diff: reiserfs:
    ignore s_bmap_nr on disk for file systems >= 8 TiB

  - patches.suse/ocfs2-06-per-resource-events.diff: Deliver
    events without a specified resource unconditionally.
    [#296606]

  - patches.fixes/proc-readdir-race-fix.patch: Fix the race
    in proc_pid_readdir [#297232]

  - patches.xen/xen3-patch-2.6.16.49-50: XEN: update to
    Linux 2.6.16.50 [#298719]

  - patches.fixes/pm-ordering-fix.patch: PM: Fix ACPI
    suspend / device suspend ordering [#302207]

  - patches.drivers/ibmvscsi-slave_configure.patch add

    ->slave_configure() to allow device restart [#304138]

  - patches.arch/ppc-power6-ebus-unique_location.patch
    Prevent bus_id collisions [#306482]

  - patches.xen/30-bit-field-booleans.patch: Fix packet loss
    in DomU xen netback driver [#306896]

  - config/i386/kdump: Enable ahci module [#308556]

  - update patches.drivers/ppc-power6-ehea.patch fix link
    state detection for bonding [#309553]

  - patches.drivers/ibmveth-fixup-pool_deactivate.patch
    patches.drivers/ibmveth-large-frames.patch
    patches.drivers/ibmveth-large-mtu.patch: fix serveral
    crashes when changing ibmveth sysfs values [#326164]

  -
    patches.drivers/libata-sata_sil24-fix-IRQ-clearing-race-
    on-I RQ_WOC: sata_sil24: fix IRQ clearing race when
    PCIX_IRQ_WOC is used [#327536]

  - update patches.drivers/ibmvscsis.patch set blocksize to
    PAGE_CACHE_SIZE to fix flood of bio allocation
    warnings/failures [#328219]

Fixes for S/390 :

  - IBM Patchcluster 17 [#330036]

  - Problem-ID: 38085 - zfcp: zfcp_scsi_eh_abort_handler or
    zfcp_scsi_eh_device_reset_handler hanging after CHPID
    off/on

  - Problem-ID: 38491 - zfcp: Error messages when LUN 0 is
    present

  - Problem-ID: 37390 - zcrypt: fix PCIXCC/CEX2C error
    recovery [#306056]

  - Problem-ID: 38500 - kernel: too few page cache pages in
    state volatile

  - Problem-ID: 38634 - qeth: crash during reboot after
    failing online setting

  - Problem-ID: 38927 - kernel: shared memory may not be
    volatile

  - Problem-ID: 39069 - cio: Disable channel path
    measurements on shutdown/reboot

  - Problem-ID: 27787 - qeth: recognize 'exclusively
    used'-RC from Hydra3

  - Problem-ID: 38330 - qeth: make qeth driver loadable
    without ipv6 module

    For further description of the named Problem-IDs, please
    look to
    http://www-128.ibm.com/developerworks/linux/linux390/oct
    ober 2005_recommended.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4571.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2007-4573.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 4471.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-bigsmp-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-default-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-smp-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-source-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-syms-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-xen-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-xenpae-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-bigsmp-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-debug-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-default-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-kdump-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-smp-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-source-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-syms-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-xen-2.6.16.53-0.16")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-xenpae-2.6.16.53-0.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
