#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4941.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(30143);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-5966", "CVE-2007-6417", "CVE-2008-0001", "CVE-2008-0007");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4941)");
  script_summary(english:"Check for the kernel-4941 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

CVE-2008-0007: Insufficient range checks in certain fault handlers
could be used by local attackers to potentially read or write kernel
memory.

CVE-2008-0001: Incorrect access mode checks could be used by local
attackers to corrupt directory contents and so cause denial of service
attacks or potentially execute code.

CVE-2007-5966: Integer overflow in the hrtimer_start function in
kernel/hrtimer.c in the Linux kernel before 2.6.23.10 allows local
users to execute arbitrary code or cause a denial of service (panic)
via a large relative timeout value. NOTE: some of these details are
obtained from third-party information.

CVE-2007-6417: The shmem_getpage function (mm/shmem.c) in Linux kernel
2.6.11 through 2.6.23 does not properly clear allocated memory in some
rare circumstances, which might allow local users to read sensitive
kernel data or cause a denial of service (crash).

Furthermore, this kernel catches up to the SLE 10 state of the kernel,
with massive additional fixes.

All platforms :

  - patches.suse/bootsplash: Bootsplash for current kernel
    (none). patch the patch for Bug number 345980.

  - patches.fixes/megaraid-fixup-driver-version: Megaraid
    driver version out of sync (299740).

  - OCFS2: Updated to version 1.2.8

  - patches.fixes/ocfs2-1.2-svn-r3070.diff: [PATCH] ocfs2:
    Remove overzealous BUG_ON().

  - patches.fixes/ocfs2-1.2-svn-r3072.diff: [PATCH] ocfs2:
    fix rename vs unlink race.

  - patches.fixes/ocfs2-1.2-svn-r3074.diff: [PATCH] ocfs2:
    Remove expensive local alloc bitmap scan code.

  - patches.fixes/ocfs2-1.2-svn-r3057.diff: [PATCH] ocfs2:
    Check for cluster locking in ocfs2_readpage.

  - patches.fixes/ocfs2-1.2-svn-r2975.diff: ocfs2_dlm: make
    functions static.

  - patches.fixes/ocfs2-1.2-svn-r2976.diff: [PATCH]
    ocfs2_dlm: make tot_backoff more descriptive.

  - patches.fixes/ocfs2-1.2-svn-r3002.diff: [PATCH] ocfs2:
    Remove the printing of harmless ERRORS like ECONNRESET,
    EPIPE..

  - patches.fixes/ocfs2-1.2-svn-r3004.diff: [PATCH]
    ocfs2_dlm: Call cond_resched_lock() once per hash bucket
    scan.

  - patches.fixes/ocfs2-1.2-svn-r3006.diff: [PATCH]
    ocfs2_dlm: Silence compiler warnings.

  - patches.fixes/ocfs2-1.2-svn-r3062.diff: [PATCH]
    ocfs2_dlm: Fix double increment of migrated lockres'
    owner count.

  - patches.fixes/hugetlb-get_user_pages-corruption.patch:
    hugetlb: follow_hugetlb_page() for write access
    (345239).

  - enable patches.fixes/reiserfs-fault-in-pages.patch
    (333412)

  - patches.drivers/usb-update-evdo-driver-ids.patch: USB:
    update evdo driver ids. Get the module to build...

- patches.drivers/usb-add-usb_device_and_interface_info.patch: USB:
add USB_DEVICE_AND_INTERFACE_INFO(). This is needed to get the HUAWEI
devices to work properly, and to get
patches.drivers/usb-update-evdo-driver-ids.patch to build without
errors.

  - patches.drivers/usb-update-evdo-driver-ids.patch: USB:
    update evdo driver ids on request from our IT department
    (345438).

  - patches.suse/kdump-dump_after_notifier.patch: Add
    dump_after_notifier sysctl (265764).

  - patches.drivers/libata-sata_nv-disable-ADMA: sata_nv:
    disable ADMA by default (346508).

  - patches.fixes/cpufreq-fix-ondemand-deadlock.patch:
    Cpufreq fix ondemand deadlock (337439).

- patches.fixes/eliminate-cpufreq_userspace-scaling_setspeed-d
eadlock.patch: Eliminate cpufreq_userspace scaling_setspeed deadlock
(337439).

  - patches.xen/15181-dma-tracking.patch: Fix issue
    preventing Xen KMPs from building.

  - patches.drivers/r8169-perform-a-PHY-reset-before.patch:
    r8169: perform a PHY reset before any other operation at
    boot time (345658).

  - patches.drivers/r8169-more-alignment-for-the-0x8168:
    refresh.

  - patches.fixes/lockd-grant-shutdown: Stop GRANT callback
    from crashing if NFS server has been stopped. (292478).
    There was a problem with this patch which would cause
    apparently random crashes when lockd was in use. The
    offending change has been removed.

  - patches.fixes/usb_336850.diff: fix missing quirk leading
    to a device disconnecting under load (336850).

  - patches.fixes/cifs-incomplete-recv.patch: fix incorrect
    session reconnects (279783).

  - patches.fixes/megaraid_mbox-dell-cerc-support: Fix so
    that it applies properly. I extended the context to 6
    lines to help patch find where to apply the patch
    (267134).

  - patches.fixes/md-idle-test: md: improve the
    is_mddev_idle test fix (326591).

AMD64/Intel EM64T (x86_64) specific :

  - patches.arch/x86_64-mce-loop: x86_64: fix misplaced
    `continue' in mce.c (344239)."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(189, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-um");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kexec-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mkinitrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:multipath-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:open-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:udev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE10\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.1", reference:"kernel-bigsmp-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-debug-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-default-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-kdump-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-smp-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-source-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-syms-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-um-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-xen-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kernel-xenpae-2.6.16.54-0.2.5") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"kexec-tools-1.101-32.45.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"mkinitrd-1.2-106.62.1") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"multipath-tools-0.4.6-25.23") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"open-iscsi-2.0.707-0.32") ) flag++;
if ( rpm_check(release:"SUSE10.1", reference:"udev-085-30.44.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-kdump / etc");
}
