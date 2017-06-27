#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-4641.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(28172);
  script_version ("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 20:11:36 $");

  script_cve_id("CVE-2006-6058", "CVE-2007-4997");

  script_name(english:"openSUSE 10 Security Update : kernel (kernel-4641)");
  script_summary(english:"Check for the kernel-4641 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update fixes the following security problems :

++ CVE-2006-6058: A local denial of service when mounting MINIX
filesystems was fixed.

++ CVE-2007-4997: A 2 byte buffer underflow in the ieee80211 stack was
fixed, which might be used by attackers in WLAN reach to crash the
machine.

and the following non security bugs :

++ Kernel update to 2.6.22.12 including fixes for: genirq, x86_64,
Infiband, networking, hwmon, device removal bug [#332612] 

++ patches.drivers/alsa-hdsp-zero-division: hdsp - Fix zero division
(mainline: 2.6.24-rc1)

++ patches.drivers/libata-ata_piix-properly_terminate_DMI_syste
m_list: Fix improperly terminated array

++ patches.rt/patch-2.6.22.1-rt4.openSUSE: updated existing patch (RT
only)

++ patches.drivers/alsa-hda-robust-probe: hda-intel - Improve HD-audio
codec probing robustness [#172330]

++ patches.drivers/alsa-hda-probe-blacklist: hda-intel - Add
probe_mask blacklist [#172330]

++ patches.fixes/megaraid_mbox-dell-cerc-support: Dell CERC support
for megaraid_mbox [#267134]

++ patches.suse/reiserfs-use-reiserfs_error.diff: updated existing
patch [#299604]

++ patches.arch/acpi_gpe_suspend_cleanup-fix.patch: ACPI: Call
acpi_enable_wakeup_device at power_off (updated) [#299882]

++ patches.suse/ocfs2-15-fix-heartbeat-write.diff: Fix heartbeat block
writing [#300730]

++ patches.suse/ocfs2-14-fix-notifier-hang.diff: Fix kernel hang
during cluster initialization [#300730]

++ patches.arch/acpi_autoload_bay.patch: updated existing patch
[#302482]

++ patches.suse/zc0301_not_claim_logitech_quickcamera.diff: stop the
zc0301 driver from claiming the Logitech QuickCam [#307055]

++ patches.fixes/aux-at_vector_size.patch: Fixed kernel auxv vector
overflow in some binfmt_misc cases [#310037]

++ patches.fixes/nfs-name-len-limit: NFS: Fix an Oops in
encode_lookup() [#325913]

++ patches.arch/acpi_lid-resume.patch: ACPI: button: send initial lid
state after add and resume [#326814]

++ patches.fixes/remove-transparent-bridge-sizing: PCI: remove
transparent bridge sizing [#331027]

++ patches.fixes/fat_optimize-count-freeclus.patch: Make scan of FAT
table faster [#331600]

++ patches.suse/reiserfs-remove-first-zero-hint.diff: reiserfs: remove
first_zero_hint (updated) [#331814]

++ patches.drivers/aic7xxx-add-suspend-resume-support: aic7xxx: Add
suspend/resume support [#332048]

++ patches.drivers/alsa-emu10k1-spdif-mem-fix: emu10k1 - Fix memory
corruption [#333314]

++ patches.drivers/alsa-hda-stac-avoid-zero-nid: Fix error probing
with STAC codecs [#333320]

++ patches.arch/acpi_ec_fix_battery.patch: Fix battery/EC issues on
Acer and Asus laptops [#334806]

++ patches.suse/reiserfs-make-per-inode-xattr-locking-more-fine

-grained.diff: fixed a bad unlock in reiserfs_xattr_get() [#336669]

++ patches.fixes/ramdisk-2.6.23-corruption_fix.diff: rd: fix data
corruption on memory pressure [#338643]

++ patches.drivers/add-wacom-pnp_devices.patch: wacom tablet pnp IDs
to 8250_pnp.c [#339288]"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-bigsmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xenpae");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:10.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE10.3", reference:"kernel-bigsmp-2.6.22.12-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-debug-2.6.22.12-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-default-2.6.22.12-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-source-2.6.22.12-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-syms-2.6.22.12-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xen-2.6.22.12-0.1") ) flag++;
if ( rpm_check(release:"SUSE10.3", reference:"kernel-xenpae-2.6.22.12-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-bigsmp / kernel-debug / kernel-default / kernel-source / etc");
}
