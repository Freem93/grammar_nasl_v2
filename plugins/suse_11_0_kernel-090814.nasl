#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-1211.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40783);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2008-5033", "CVE-2009-1046", "CVE-2009-1385", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-2692");

  script_name(english:"openSUSE Security Update : kernel (kernel-1211)");
  script_summary(english:"Check for the kernel-1211 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This kernel update for openSUSE 11.0 fixes some bugs and several
security problems.

The following security issues are fixed: CVE-2009-2692: A missing NULL
pointer check in the socket sendpage function can be used by local
attackers to gain root privileges.

CVE-2009-2406: A kernel stack overflow when mounting eCryptfs
filesystems in parse_tag_11_packet() was fixed. Code execution might
be possible of ecryptfs is in use.

CVE-2009-2407: A kernel heap overflow when mounting eCryptfs
filesystems in parse_tag_3_packet() was fixed. Code execution might be
possible of ecryptfs is in use.

The compiler option -fno-delete-null-pointer-checks was added to the
kernel build, and the -fwrapv compiler option usage was fixed to be
used everywhere. This works around the compiler removing checks too
aggressively.

CVE-2009-1389: A crash in the r8169 driver when receiving large
packets was fixed. This is probably exploitable only in the local
network.

CVE-2009-1895: Personality flags on set*id were not cleared correctly,
so ASLR and NULL page protection could be bypassed.

CVE-2009-1046: A utf-8 console memory corruption that can be used for
local privilege escalation was fixed.

The NULL page protection using mmap_min_addr was enabled (was disabled
before).

No CVE yet: A sigaltstack kernel memory disclosure was fixed.

CVE-2008-5033: A local denial of service (Oops) in video4linux tvaudio
was fixed.

CVE-2009-1385: A Integer underflow in the e1000_clean_rx_irq function
in drivers/net/e1000/e1000_main.c in the e1000 driver the e1000e
driver in the Linux kernel, and Intel Wired Ethernet (aka e1000)
before 7.5.5 allows remote attackers to cause a denial of service
(panic) via a crafted frame size."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=444982"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=474549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=478699"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=503870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=509822"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=511243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=521427"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=523719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=527848"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=530151"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 119, 189, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.0", reference:"acerhk-kmp-debug-0.5.35_2.6.25.20_0.5-98.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"acx-kmp-debug-20080210_2.6.25.20_0.5-3.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"appleir-kmp-debug-1.1_2.6.25.20_0.5-108.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"at76_usb-kmp-debug-0.17_2.6.25.20_0.5-2.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"atl2-kmp-debug-2.0.4_2.6.25.20_0.5-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"aufs-kmp-debug-cvs20080429_2.6.25.20_0.5-13.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"dazuko-kmp-debug-2.3.4.4_2.6.25.20_0.5-42.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"drbd-kmp-debug-8.2.6_2.6.25.20_0.5-0.2") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"gspcav-kmp-debug-01.00.20_2.6.25.20_0.5-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"iscsitarget-kmp-debug-0.4.15_2.6.25.20_0.5-63.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"ivtv-kmp-debug-1.0.3_2.6.25.20_0.5-66.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-debug-2.6.25.20-0.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-default-2.6.25.20-0.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-pae-2.6.25.20-0.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-source-2.6.25.20-0.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-syms-2.6.25.20-0.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-vanilla-2.6.25.20-0.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-xen-2.6.25.20-0.5") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kqemu-kmp-debug-1.3.0pre11_2.6.25.20_0.5-7.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"nouveau-kmp-debug-0.10.1.20081112_2.6.25.20_0.5-0.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"omnibook-kmp-debug-20080313_2.6.25.20_0.5-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcc-acpi-kmp-debug-0.9_2.6.25.20_0.5-4.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"pcfclock-kmp-debug-0.44_2.6.25.20_0.5-207.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"tpctl-kmp-debug-4.17_2.6.25.20_0.5-189.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"uvcvideo-kmp-debug-r200_2.6.25.20_0.5-2.4") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"virtualbox-ose-kmp-debug-1.5.6_2.6.25.20_0.5-33.3") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"vmware-kmp-debug-2008.04.14_2.6.25.20_0.5-21.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"wlan-ng-kmp-debug-0.2.8_2.6.25.20_0.5-107.1") ) flag++;

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
