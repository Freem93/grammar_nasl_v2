#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-2089.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45010);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-4020", "CVE-2010-0307", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622");

  script_name(english:"openSUSE Security Update : kernel (kernel-2089)");
  script_summary(english:"Check for the kernel-2089 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.0 kernel was updated to fix following security 
issues :

CVE-2009-4020: Stack-based buffer overflow in the hfs subsystem in the
Linux kernel 2.6.32 allows remote attackers to have an unspecified
impact via a crafted Hierarchical File System (HFS) filesystem,
related to the hfs_readdir function in fs/hfs/dir.c.

CVE-2010-0307: The load_elf_binary function in fs/binfmt_elf.c in the
Linux kernel before 2.6.32.8 on the x86_64 platform does not ensure
that the ELF interpreter is available before a call to the
SET_PERSONALITY macro, which allows local users to cause a denial of
service (system crash) via a 32-bit application that attempts to
execute a 64-bit application and then triggers a segmentation fault,
as demonstrated by amd64_killer, related to the flush_old_exec
function.

CVE-2010-0622: The wake_futex_pi function in kernel/futex.c in the
Linux kernel before 2.6.33-rc7 does not properly handle certain unlock
operations for a Priority Inheritance (PI) futex, which allows local
users to cause a denial of service (OOPS) and possibly have
unspecified other impact via vectors involving modification of the
futex value from user space.

CVE-2010-0410: drivers/connector/connector.c in the Linux kernel
before 2.6.32.8 allows local users to cause a denial of service
(memory consumption and system crash) by sending the kernel many
NETLINK_CONNECTOR messages.

CVE-2010-0415: The do_pages_move function in mm/migrate.c in the Linux
kernel before 2.6.33-rc7 does not validate node values, which allows
local users to read arbitrary kernel memory locations, cause a denial
of service (OOPS), and possibly have unspecified other impact by
specifying a node that is not part of the kernel's node set."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=564374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=577753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=579439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=581718"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acerhk-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:acx-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:appleir-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:at76_usb-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:atl2-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:aufs-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:dazuko-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:drbd-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:gspcav-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:iscsitarget-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ivtv-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kqemu-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nouveau-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:omnibook-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcc-acpi-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pcfclock-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tpctl-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uvcvideo-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:virtualbox-ose-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vmware-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wlan-ng-kmp-debug");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"acerhk-kmp-debug-0.5.35_2.6.25.20_0.7-98.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"acx-kmp-debug-20080210_2.6.25.20_0.7-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"appleir-kmp-debug-1.1_2.6.25.20_0.7-108.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"at76_usb-kmp-debug-0.17_2.6.25.20_0.7-2.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"atl2-kmp-debug-2.0.4_2.6.25.20_0.7-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"aufs-kmp-debug-cvs20080429_2.6.25.20_0.7-13.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"dazuko-kmp-debug-2.3.4.4_2.6.25.20_0.7-42.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"drbd-kmp-debug-8.2.6_2.6.25.20_0.7-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"gspcav-kmp-debug-01.00.20_2.6.25.20_0.7-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"iscsitarget-kmp-debug-0.4.15_2.6.25.20_0.7-63.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ivtv-kmp-debug-1.0.3_2.6.25.20_0.7-66.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-debug-2.6.25.20-0.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-default-2.6.25.20-0.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-pae-2.6.25.20-0.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-source-2.6.25.20-0.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-syms-2.6.25.20-0.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-vanilla-2.6.25.20-0.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-xen-2.6.25.20-0.7") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kqemu-kmp-debug-1.3.0pre11_2.6.25.20_0.7-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"nouveau-kmp-debug-0.10.1.20081112_2.6.25.20_0.7-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"omnibook-kmp-debug-20080313_2.6.25.20_0.7-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcc-acpi-kmp-debug-0.9_2.6.25.20_0.7-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcfclock-kmp-debug-0.44_2.6.25.20_0.7-207.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tpctl-kmp-debug-4.17_2.6.25.20_0.7-189.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"uvcvideo-kmp-debug-r200_2.6.25.20_0.7-2.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"virtualbox-ose-kmp-debug-1.5.6_2.6.25.20_0.7-33.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"vmware-kmp-debug-2008.04.14_2.6.25.20_0.7-21.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"wlan-ng-kmp-debug-0.2.8_2.6.25.20_0.7-107.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "acerhk-kmp-debug / acx-kmp-debug / appleir-kmp-debug / etc");
}
