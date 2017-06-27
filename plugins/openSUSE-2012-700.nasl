#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-700.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74778);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-3412", "CVE-2012-3520");

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2012:1330-1)");
  script_summary(english:"Check for the openSUSE-2012-700 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update to 3.4.11 fixes various bugs and security issues.

The changes up to 3.4.11 contain both security and bugfixes and are
not explicitly listed here.

Following security issues were fixed: CVE-2012-3520: Force passing
credentials, otherwise local services could be fooled to assume
requests coming from root.

CVE-2012-3412: Do not allow extreme TSO parameters in the sfc driver
and tcp stack.

Following non-security bugs were fixed :

  - nbd: clear waiting_queue on shutdown (bnc#778630).

  - NFS: avoid warning from nfs_drop_nlink (bnc#780624).

  - net: do not disable sg for packets requiring no checksum
    (bnc#774859).

  - sfc: Fix maximum number of TSO segments and minimum TX
    queue size (bnc#774523 CVE-2012-3412).

  - net: Allow driver to limit number of GSO segments per
    skb (bnc#774523 CVE-2012-3412).

  - drm/nouveau: fix booting with plymouth + dumb support
    (bnc#771392).

  - memcg: warn on deeper hierarchies with use_hierarchy==0
    (bnc#781134).

  - Linux 3.4.11.

  - Update config files.

  - Refresh patches.suse/scsi-error-test-unit-ready-timeout.

  - Btrfs: fix tree log remove space corner case
    (bnc#779432)

  - irq_remap: disable IRQ remapping if any IOAPIC lacks an
    IOMMU.

  - Linux 3.4.10.

  - Linux 3.4.9.

  - kABI: protect struct irq_desc.

  - Linux 3.4.8.

  - kABI: sdhci, remove inclusion.

  - reiserfs: fix deadlock with nfs racing on create/lookup
    (bnc#762693).

  - Properly update Xen patches to 3.4.7.

  - Refresh other Xen patches (bnc#772831).

  - config: enable various ARM errata workarounds to improve
    stability

  - Import kabi files for 12.2

  - rpm/config.sh: Build the KOTD against 12.2

  - ASoC: omap: Add missing modules aliases to get sound
    working on omap devices.

  - Update config files to fix build

  - rt2800: add chipset revision RT5390R support
    (bnc#772566).

  - reiserfs: fix deadlocks with quotas

  - ACPI, APEI: Fixup common access width firmware bug
    (bnc#765230).

  - i2c/busses: Fix build error if
    CONFIG_I2C_DESIGNWARE_PLATFORM=y and CONFIG_I2C_DESIGN.

  - Update ARM configs to match kernel 3.4.7

  - Update ARM omap2plus config to match kernel 3.4.7 and
    add Smartreflex support (auto voltage)

  - ALSA: hda - Fix mute-LED GPIO initialization for IDT
    codecs (bnc#772923).

  - ALSA: hda - Fix polarity of mute LED on HP Mini 210
    (bnc#772923).

  - Linux 3.4.7.

  - Refresh patches.suse/dm-raid45-26-Nov-2009.patch.

  - Enable RTL8150 for omap2plus Generic USB Network device
    that also works fine on ARM, so enable it

  - update RNDIS_OID_GEN_RNDIS_CONFIG_PARAMETER patch name

  - Drivers: hv: Cleanup the guest ID computation.

  - hyperv: Add a check for ring_size value.

  - hyperv: Add error handling to rndis_filter_device_add().

  - Drivers: hv: Change the hex constant to a decimal
    constant.

  - hyperv: Add support for setting MAC from within guests.

  - net/hyperv: Use wait_event on outstanding sends during
    device removal.

  - hv: add RNDIS_OID_GEN_RNDIS_CONFIG_PARAMETER.

  - Refresh patches.suse/SUSE-bootsplash. Fix wrong vfree()
    (bnc#773406)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-10/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=762693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=765230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=771392"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=772923"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=774859"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=776925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=779432"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=780624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=781134"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-ec2-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-default-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-source-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-source-vanilla-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"kernel-syms-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-extra-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-ec2-extra-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-extra-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-ec2-extra-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-base-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-debugsource-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-devel-3.4.11-2.16.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.4.11-2.16.1") ) flag++;

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
