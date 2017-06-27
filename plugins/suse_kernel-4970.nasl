#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4970.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(30250);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2007-3843", "CVE-2007-5966", "CVE-2007-6417", "CVE-2008-0001", "CVE-2008-0007");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4970)");
  script_summary(english:"Check for the kernel-4970 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update is a respin of a previous one that broke CPUFREQ
support (bug 357598).

Previous changes :

This kernel update fixes the following security problems :

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

CVE-2007-3843: The Linux kernel checked the wrong global variable for
the CIFS sec mount option, which might allow remote attackers to spoof
CIFS network traffic that the client configured for security
signatures, as demonstrated by lack of signing despite sec=ntlmv2i in
a SetupAndX request.

CVE-2007-6417: The shmem_getpage function (mm/shmem.c) in Linux kernel
2.6.11 through 2.6.23 does not properly clear allocated memory in some
rare circumstances, which might allow local users to read sensitive
kernel data or cause a denial of service (crash).

And the following bugs (numbers are https://bugzilla.novell.com/
references) :

  - patches.fixes/input-add-amilo-pro-v-to-nomux.patch: Add
    Fujitsu-Siemens Amilo Pro 2010 to nomux list (345699).

  - patches.arch/acpica-psd.patch: Changed resolution of
    named references in packages
    (https://bugzilla.novell.com/show_bug.cgi?id=346831).

  - patches.fixes/acpica_sizeof.patch: SizeOf operator ACPI
    interpreter fix
    (http://bugzilla.kernel.org/show_bug.cgi?id=9558).

  - patches.drivers/libata-sata_sis-fix-scr-access:
    sata_sis: fix SCR access (331610).

  - patches.drivers/libata-tape-fix: libata: backport tape
    support fixes (345438).

  - patches.arch/powernowk8_family_freq_from_fiddid.patch:
    To find the frequency given the fid and did is family
    dependent. (#332722).

  - patches.drivers/libata-force-cable-type: libata:
    implement libata.force_cbl parameter (337610).

  - patches.drivers/libata-sata_nv-disable-ADMA: sata_nv:
    disable ADMA by default (346508).

  - patches.fixes/via-velocity-dont-oops-on-mtu-change-1:
    [VIA_VELOCITY]: Don't oops on MTU change. (341537).

  - patches.fixes/via-velocity-dont-oops-on-mtu-change-2:
    via-velocity: don't oops on MTU change while down
    (341537).

- patches.fixes/sony-laptop-call-sonypi_compat_init-earlier: s
ony-laptop: call sonypi_compat_init earlier (343483).

  - Updated kABI symbols for 2.6.22.15 changes, and Xen
    x86_64 changes.

  - series.conf file cleanup: group together latency tracing
    patches.

  - Fix a memory leak and a panic in drivers/block/cciss.c
    patches.drivers/cciss-panic-in-blk_rq_map_sg: Panic in
    blk_rq_map_sg() from CCISS driver.

  - patches.drivers/cciss-fix_memory_leak :

  - Address missed-interrupt issues discovered upstream.

  - Update to 2.6.22.15

  - fixes CVE-2007-5966

  - lots of libata fixes, which cause the following to be
    removed :

    -
    patches.drivers/libata-add-NCQ-spurious-completion-horka
    ges

    -
    patches.drivers/libata-add-ST9120822AS-to-NCQ-blacklist

    -
    patches.drivers/libata-disable-NCQ-for-ST9160821AS-3.ALD

  - removed patches already in this release :

    -
    patches.fixes/i4l-avoid-copying-an-overly-long-string.pa
    tch :

  - patches.fixes/ramdisk-2.6.23-corruption_fix.diff

  - patches.fixes/microtek_hal.diff: Delete.

  - fixed previous poweroff regression from 2.6.22.10

  - lots of other fixes and some new pci ids.

  - Thousands of changes in patches.rt/ for the kernel-rt*
    kernels.

  - patches.fixes/usb_336850.diff: fix missing quirk leading
    to a device disconnecting under load (336850).

  - patches.fixes/nfs-unmount-leak.patch: NFSv2/v3: Fix a
    memory leak when using -onolock (336253).

  - add xenfb-module-param patch to make Xen virtual frame
    buffer configurable in the guest domains, instead of a
    fixed resolution of 800x600.

  - patches.xen/xen3-aux-at_vector_size.patch: Also include
    x86-64 (310037).

  - patches.xen/xen3-patch-2.6.18: Fix system lockup
    (335121).

  - patches.fixes/acpi_autoload_baydock.patch: autloading of
    dock module (302482). Fixed a general bug with linux
    specific hids there.

  - patches.xen/xen3-patch-2.6.22.11-12: Linux 2.6.22.12.

  - patches.xen/xen3-fixup-arch-i386: Fix CONFIG_APM=m
    issue.

  - patches.xen/xen-x86-no-lapic: Re-diff."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugzilla.kernel.org/show_bug.cgi?id=9558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=346831"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
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
if (release !~ "^(SUSE10\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "10.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-rt-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-rt_debug-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.16-0.2") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.16-0.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-rt / etc");
}
