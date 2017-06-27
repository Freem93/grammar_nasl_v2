#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-2050.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44964);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/21 20:09:51 $");

  script_cve_id("CVE-2009-3939", "CVE-2009-4536", "CVE-2009-4538", "CVE-2010-0003", "CVE-2010-0007", "CVE-2010-0307", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622");

  script_name(english:"openSUSE Security Update : kernel (kernel-2050)");
  script_summary(english:"Check for the kernel-2050 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.1 Kernel was updated to 2.6.27.42 fixing various bugs
and security issues.

CVE-2010-0622: The wake_futex_pi function in kernel/futex.c in the
Linux kernel before 2.6.33-rc7 does not properly handle certain unlock
operations for a Priority Inheritance (PI) futex, which allows local
users to cause a denial of service (OOPS) and possibly have
unspecified other impact via vectors involving modification of the
futex value from user space.

CVE-2010-0307: The load_elf_binary function in fs/binfmt_elf.c in the
Linux kernel before 2.6.32.8 on the x86_64 platform does not ensure
that the ELF interpreter is available before a call to the
SET_PERSONALITY macro, which allows local users to cause a denial of
service (system crash) via a 32-bit application that attempts to
execute a 64-bit application and then triggers a segmentation fault,
as demonstrated by amd64_killer, related to the flush_old_exec
function.

CVE-2010-0410: Users could send/allocate arbitrary amounts of
NETLINK_CONNECTOR messages to the kernel, causing OOM condition,
killing selected processes or halting the system.

CVE-2010-0415: The do_pages_move function in mm/migrate.c in the Linux
kernel before 2.6.33-rc7 does not validate node values, which allows
local users to read arbitrary kernel memory locations, cause a denial
of service (OOPS), and possibly have unspecified other impact by
specifying a node that is not part of the kernel's node set.

CVE-2010-0007: net/bridge/netfilter/ebtables.c in the ebtables module
in the netfilter framework in the Linux kernel before 2.6.33-rc4 does
not require the CAP_NET_ADMIN capability for setting or modifying
rules, which allows local users to bypass intended access restrictions
and configure arbitrary network-traffic filtering via a modified
ebtables application.

CVE-2009-4536: drivers/net/e1000/e1000_main.c in the e1000 driver in
the Linux kernel 2.6.32.3 and earlier handles Ethernet frames that
exceed the MTU by processing certain trailing payload data as if it
were a complete frame, which allows remote attackers to bypass packet
filters via a large packet with a crafted payload.

CVE-2009-4538: drivers/net/e1000e/netdev.c in the e1000e driver in the
Linux kernel 2.6.32.3 and earlier does not properly check the size of
an Ethernet frame that exceeds the MTU, which allows remote attackers
to have an unspecified impact via crafted packets.

CVE-2010-0003: The print_fatal_signal function in kernel/signal.c in
the Linux kernel before 2.6.32.4 on the i386 platform, when
print-fatal-signals is enabled, allows local users to discover the
contents of arbitrary memory locations by jumping to an address and
then reading a log file, and might allow local users to cause a denial
of service (system slowdown or crash) by jumping to an address.

CVE-2009-3939: The poll_mode_io file for the megaraid_sas driver in
the Linux kernel 2.6.31.6 and earlier has world-writable permissions,
which allows local users to change the I/O mode of the driver by
modifying this file."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=474773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=492961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=510449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=534629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=537016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=547433"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=553175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=554567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=556282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=561078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=566634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=566768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=566857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=567376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569071"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=569902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=570314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=570606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=571804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=573478"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=574224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=575644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576277"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=580047"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=580354"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=581718"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/03");
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
if (release !~ "^(SUSE11\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-base-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-debug-extra-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-base-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-default-extra-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-base-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-pae-extra-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-source-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-syms-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-base-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-trace-extra-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-vanilla-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-base-2.6.27.45-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.1", reference:"kernel-xen-extra-2.6.27.45-0.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-extra / etc");
}
