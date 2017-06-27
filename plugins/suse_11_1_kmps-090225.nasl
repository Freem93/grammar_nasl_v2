#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kmps-562.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40251);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/06/13 19:49:34 $");

  script_name(english:"openSUSE Security Update : kmps (kmps-562)");
  script_summary(english:"Check for the kmps-562 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update contains kernel module packages for the first openSUSE
11.1 kernel update.

It contains all kernel module packages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=444597"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected kmps packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acx-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acx-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acx-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acx-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acx-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:appleir-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:appleir-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:appleir-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:appleir-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:appleir-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brocade-bfa-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brocade-bfa-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brocade-bfa-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brocade-bfa-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brocade-bfa-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hci_usb-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hci_usb-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hci_usb-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hci_usb-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hci_usb-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:intel-iamt-heci-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:intel-iamt-heci-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:intel-iamt-heci-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:intel-iamt-heci-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:intel-iamt-heci-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kvm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kvm-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kvm-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lirc-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lirc-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lirc-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:lirc-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ndiswrapper-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ofed-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ofed-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ofed-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ofed-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:omnibook-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:omnibook-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:omnibook-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:omnibook-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:omnibook-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:oracleasm-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:oracleasm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:oracleasm-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:oracleasm-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:oracleasm-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quickcam-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:quickcam-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-guest-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wacom-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wacom-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wacom-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wacom-kmp-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wacom-kmp-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-driver-virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"acx-kmp-debug-20080210_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acx-kmp-default-20080210_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acx-kmp-pae-20080210_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acx-kmp-trace-20080210_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"acx-kmp-xen-20080210_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"appleir-kmp-debug-1.1_2.6.27.19_3.2-114.65.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"appleir-kmp-default-1.1_2.6.27.19_3.2-114.65.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"appleir-kmp-pae-1.1_2.6.27.19_3.2-114.65.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"appleir-kmp-trace-1.1_2.6.27.19_3.2-114.65.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"appleir-kmp-xen-1.1_2.6.27.19_3.2-114.65.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-debug-cvs20081020_2.6.27.19_3.2-1.32.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-default-cvs20081020_2.6.27.19_3.2-1.32.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-pae-cvs20081020_2.6.27.19_3.2-1.32.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-trace-cvs20081020_2.6.27.19_3.2-1.32.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"aufs-kmp-xen-cvs20081020_2.6.27.19_3.2-1.32.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-debug-1.1.0.2_2.6.27.19_3.2-1.7.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-default-1.1.0.2_2.6.27.19_3.2-1.7.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-pae-1.1.0.2_2.6.27.19_3.2-1.7.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-trace-1.1.0.2_2.6.27.19_3.2-1.7.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"brocade-bfa-kmp-xen-1.1.0.2_2.6.27.19_3.2-1.7.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-debug-2.3.6_2.6.27.19_3.2-1.49.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-default-2.3.6_2.6.27.19_3.2-1.49.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-pae-2.3.6_2.6.27.19_3.2-1.49.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-trace-2.3.6_2.6.27.19_3.2-1.49.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"dazuko-kmp-xen-2.3.6_2.6.27.19_3.2-1.49.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-debug-8.2.7_2.6.27.19_3.2-1.18.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-default-8.2.7_2.6.27.19_3.2-1.18.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-pae-8.2.7_2.6.27.19_3.2-1.18.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-trace-8.2.7_2.6.27.19_3.2-1.18.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"drbd-kmp-xen-8.2.7_2.6.27.19_3.2-1.18.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"hci_usb-kmp-default-0.1_2.6.27.19_3.2-2.47.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"hci_usb-kmp-pae-0.1_2.6.27.19_3.2-2.47.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"hci_usb-kmp-trace-0.1_2.6.27.19_3.2-2.47.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"hci_usb-kmp-xen-0.1_2.6.27.19_3.2-2.47.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-debug-3.1.0.31_2.6.27.19_3.2-2.40.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-default-3.1.0.31_2.6.27.19_3.2-2.40.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-pae-3.1.0.31_2.6.27.19_3.2-2.40.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-trace-3.1.0.31_2.6.27.19_3.2-2.40.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"intel-iamt-heci-kmp-xen-3.1.0.31_2.6.27.19_3.2-2.40.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-debug-0.4.15_2.6.27.19_3.2-89.11.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-default-0.4.15_2.6.27.19_3.2-89.11.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-pae-0.4.15_2.6.27.19_3.2-89.11.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-trace-0.4.15_2.6.27.19_3.2-89.11.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"iscsitarget-kmp-xen-0.4.15_2.6.27.19_3.2-89.11.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-debug-1.4.0pre1_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-default-1.4.0pre1_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-pae-1.4.0pre1_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-trace-1.4.0pre1_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kqemu-kmp-xen-1.4.0pre1_2.6.27.19_3.2-2.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kvm-kmp-default-78_2.6.27.19_3.2-6.6.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kvm-kmp-pae-78_2.6.27.19_3.2-6.6.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kvm-kmp-trace-78_2.6.27.19_3.2-6.6.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"lirc-kmp-default-0.8.4_2.6.27.19_3.2-0.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"lirc-kmp-pae-0.8.4_2.6.27.19_3.2-0.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"lirc-kmp-trace-0.8.4_2.6.27.19_3.2-0.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"lirc-kmp-xen-0.8.4_2.6.27.19_3.2-0.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ndiswrapper-kmp-default-1.53_2.6.27.19_3.2-12.37.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ndiswrapper-kmp-pae-1.53_2.6.27.19_3.2-12.37.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ndiswrapper-kmp-trace-1.53_2.6.27.19_3.2-12.37.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ndiswrapper-kmp-xen-1.53_2.6.27.19_3.2-12.37.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-debug-1.4_2.6.27.19_3.2-21.15.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-default-1.4_2.6.27.19_3.2-21.15.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-pae-1.4_2.6.27.19_3.2-21.15.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"ofed-kmp-trace-1.4_2.6.27.19_3.2-21.15.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"omnibook-kmp-debug-20080627_2.6.27.19_3.2-1.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"omnibook-kmp-default-20080627_2.6.27.19_3.2-1.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"omnibook-kmp-pae-20080627_2.6.27.19_3.2-1.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"omnibook-kmp-trace-20080627_2.6.27.19_3.2-1.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"omnibook-kmp-xen-20080627_2.6.27.19_3.2-1.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-debug-2.0.5_2.6.27.19_3.2-2.36.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-default-2.0.5_2.6.27.19_3.2-2.36.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-pae-2.0.5_2.6.27.19_3.2-2.36.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-trace-2.0.5_2.6.27.19_3.2-2.36.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"oracleasm-kmp-xen-2.0.5_2.6.27.19_3.2-2.36.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-debug-0.44_2.6.27.19_3.2-227.56.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-default-0.44_2.6.27.19_3.2-227.56.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-pae-0.44_2.6.27.19_3.2-227.56.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"pcfclock-kmp-trace-0.44_2.6.27.19_3.2-227.56.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"quickcam-kmp-default-0.6.6_2.6.27.19_3.2-9.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"quickcam-kmp-pae-0.6.6_2.6.27.19_3.2-9.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-2.0.6-2.8.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-guest-tools-2.0.6-2.8.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-debug-2.0.6_2.6.27.19_3.2-2.8.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-default-2.0.6_2.6.27.19_3.2-2.8.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-pae-2.0.6_2.6.27.19_3.2-2.8.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"virtualbox-ose-kmp-trace-2.0.6_2.6.27.19_3.2-2.8.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-debug-2008.09.03_2.6.27.19_3.2-5.50.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-default-2008.09.03_2.6.27.19_3.2-5.50.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-pae-2008.09.03_2.6.27.19_3.2-5.50.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"vmware-kmp-trace-2008.09.03_2.6.27.19_3.2-5.50.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"wacom-kmp-debug-0.8.1_2.6.27.19_3.2-6.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"wacom-kmp-default-0.8.1_2.6.27.19_3.2-6.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"wacom-kmp-pae-0.8.1_2.6.27.19_3.2-6.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"wacom-kmp-trace-0.8.1_2.6.27.19_3.2-6.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"wacom-kmp-xen-0.8.1_2.6.27.19_3.2-6.1.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"xorg-x11-driver-virtualbox-ose-2.0.6-2.8.6") ) flag++;
if ( rpm_check(release:"SUSE11.1", cpu:"x86_64", reference:"hci_usb-kmp-debug-0.1_2.6.27.19_3.2-2.47.6") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acx-kmp-debug / acx-kmp-default / acx-kmp-pae / acx-kmp-trace / etc");
}
