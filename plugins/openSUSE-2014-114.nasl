#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-114.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75252);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/10 14:25:16 $");

  script_cve_id("CVE-2013-4511", "CVE-2013-4563", "CVE-2013-4587", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6432", "CVE-2014-0038");
  script_bugtraq_id(63512, 63702, 64135, 64270, 64291, 64319, 64328, 65255);

  script_name(english:"openSUSE Security Update : kernel (openSUSE-SU-2014:0205-1)");
  script_summary(english:"Check for the openSUSE-2014-114 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Linux Kernel was updated to version 3.11.10, fixing security
issues and bugs :

  - floppy: bail out in open() if drive is not responding to
    block0 read (bnc#773058).

  - compat_sys_recvmmsg X32 fix (bnc#860993 CVE-2014-0038).

  - HID: usbhid: fix sis quirk (bnc#859804).

  - hwmon: (coretemp) Fix truncated name of alarm attributes

  - HID: usbhid: quirk for Synaptics Quad HD touchscreen
    (bnc#859804).

  - HID: usbhid: quirk for Synaptics HD touchscreen
    (bnc#859804).

  - HID: usbhid: merge the sis quirk (bnc#859804).

  - HID: hid-multitouch: add support for SiS panels
    (bnc#859804).

  - HID: usbhid: quirk for SiS Touchscreen (bnc#859804).

  - HID: usbhid: quirk for Synaptics Large Touchccreen
    (bnc#859804).

  - drivers: net: cpsw: fix dt probe for one port ethernet.

  - drivers: net: cpsw: fix for cpsw crash when build as
    modules.

  - dma: edma: Remove limits on number of slots.

  - dma: edma: Leave linked to Null slot instead of DUMMY
    slot.

  - dma: edma: Find missed events and issue them.

  - dma: edma: Write out and handle MAX_NR_SG at a given
    time.

  - dma: edma: Setup parameters to DMA MAX_NR_SG at a time.

  - ARM: edma: Add function to manually trigger an EDMA
    channel.

  - ARM: edma: Fix clearing of unused list for DT DMA
    resources.

  - ACPI: Add Toshiba NB100 to Vista _OSI blacklist.

  - ACPI: add missing win8 OSI comment to blacklist
    (bnc#856294).

  - ACPI: update win8 OSI blacklist.

  - ACPI: blacklist win8 OSI for buggy laptops.

  - ACPI: blacklist win8 OSI for ASUS Zenbook Prime UX31A
    (bnc#856294).

  - ACPI: Blacklist Win8 OSI for some HP laptop 2013 models
    (bnc#856294).

  - floppy: bail out in open() if drive is not responding to
    block0 read (bnc#773058).

  - ping: prevent NULL pointer dereference on write to
    msg_name (bnc#854175 CVE-2013-6432).

  - x86/dumpstack: Fix printk_address for direct addresses
    (bnc#845621).

  - Refresh patches.suse/stack-unwind.

  - Refresh patches.xen/xen-x86_64-dump-user-pgt.

  - KVM: x86: Convert vapic synchronization to _cached
    functions (CVE-2013-6368) (bnc#853052 CVE-2013-6368).

  - KVM: x86: fix guest-initiated crash with x2apic
    (CVE-2013-6376) (bnc#853053 CVE-2013-6376).

  - Build the KOTD against openSUSE:13.1:Update

  - xencons: generalize use of add_preferred_console()
    (bnc#733022, bnc#852652).

  - Update Xen patches to 3.11.10.

  - Rename patches.xen/xen-pcpu-hotplug to
    patches.xen/xen-pcpu.

  - KVM: x86: Fix potential divide by 0 in lapic
    (CVE-2013-6367) (bnc#853051 CVE-2013-6367).

  - KVM: Improve create VCPU parameter (CVE-2013-4587)
    (bnc#853050 CVE-2013-4587).

  - ipv6: fix headroom calculation in udp6_ufo_fragment
    (bnc#848042 CVE-2013-4563).

  - net: rework recvmsg handler msg_name and msg_namelen
    logic (bnc#854722).

  - patches.drivers/gpio-ucb1400-add-module_alias.patch:
    Update upstream reference

  -
    patches.drivers/gpio-ucb1400-can-be-built-as-a-module.pa
    tch: Update upstream reference

  - Delete patches.suse/ida-remove-warning-dump-stack.patch.
    Already included in kernel 3.11 (WARN calls dump_stack.)

  - xhci: Limit the spurious wakeup fix only to HP machines
    (bnc#852931).

  - iscsi_target: race condition on shutdown (bnc#850072).

  - Linux 3.11.10.

  - Refresh patches.xen/xen3-patch-2.6.29.

  - Delete
    patches.suse/btrfs-relocate-csums-properly-with-prealloc
    -extents.patch.

  -
    patches.drivers/xhci-Fix-spurious-wakeups-after-S5-on-Ha
    swell.patch: (bnc#852931).

  - Build mei and mei_me as modules (bnc#852656)

  - Linux 3.11.9.

  - Linux 3.11.8 (CVE-2013-4511 bnc#846529 bnc#849021).

  - Delete
    patches.drivers/ALSA-hda-Add-a-fixup-for-ASUS-N76VZ.

  - Delete
    patches.fixes/Fix-a-few-incorrectly-checked-io_-remap_pf
    n_range-ca.patch.

  - Add USB PHY support (needed to get USB and Ethernet
    working on beagle and panda boards) Add
    CONFIG_PINCTRL_SINGLE=y to be able to use Device tree
    (at least for beagle and panda boards) Add ARM SoC sound
    support Add SPI bus support Add user-space access to I2C
    and SPI

  -
    patches.arch/iommu-vt-d-remove-stack-trace-from-broken-i
    rq-remapping-warning.patch: Fix forward porting, sorry.

  - iommu: Remove stack trace from broken irq remapping
    warning (bnc#844513).

  - gpio: ucb1400: Add MODULE_ALIAS.

  - Allow NFSv4 username mapping to work properly
    (bnc#838024).

  - nfs: check if gssd is running before attempting to use
    krb5i auth in SETCLIENTID call.

  - sunrpc: replace sunrpc_net->gssd_running flag with a
    more reliable check.

  - sunrpc: create a new dummy pipe for gssd to hold open.

  - Set CONFIG_GPIO_TWL4030 as built-in (instead of module)
    as a requirement to boot on SD card on beagleboard xM

  - armv6hl, armv7hl: Update config files. Set
    CONFIG_BATMAN_ADV_BLA=y as all other kernel
    configuration files have.

  - Update config files :

  - CONFIG_BATMAN_ADV_NC=y, because other BATMAN_ADV options
    are all enabled so why not this one.

  - CONFIG_GPIO_SCH=m, CONFIG_GPIO_PCH=m, because we support
    all other features of these pieces of hardware.

  - CONFIG_INTEL_POWERCLAMP=m, because this small driver
    might be useful in specific cases, and there's no
    obvious reason not to include it.

  - Fix a few incorrectly checked [io_]remap_pfn_range()
    calls (bnc#849021, CVE-2013-4511).

  - Linux 3.11.7."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-02/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=733022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=773058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=838024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=844513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=846529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=848042"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=849021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=850072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=852931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853052"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=853053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=854722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=856294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=859804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=860993"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 3.13.1 Recvmmsg Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-default-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-source-vanilla-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"kernel-syms-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-debug-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-desktop-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-ec2-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-pae-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-trace-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-vanilla-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"i686", reference:"kernel-xen-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-debug-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-desktop-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-ec2-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-pae-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-trace-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-vanilla-devel-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-base-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debuginfo-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-debugsource-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-3.11.10-7.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", cpu:"x86_64", reference:"kernel-xen-devel-debuginfo-3.11.10-7.1") ) flag++;

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
