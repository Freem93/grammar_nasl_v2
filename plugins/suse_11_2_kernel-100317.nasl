#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-2146.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(45128);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-4031", "CVE-2010-0410", "CVE-2010-0415", "CVE-2010-0622", "CVE-2010-0623");

  script_name(english:"openSUSE Security Update : kernel (kernel-2146)");
  script_summary(english:"Check for the kernel-2146 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the openSUSE 11.2 kernel contains a lot of bug and
security fixes.

Following security issues were fixed: CVE-2010-0622: The wake_futex_pi
function in kernel/futex.c in the Linux kernel does not properly
handle certain unlock operations for a Priority Inheritance (PI)
futex, which allows local users to cause a denial of service (OOPS)
and possibly have unspecified other impact via vectors involving
modification of the futex value from user space.

CVE-2010-0623: The futex_lock_pi function in kernel/futex.c in the
Linux kernel does not properly manage a certain reference count, which
allows local users to cause a denial of service (OOPS) via vectors
involving an unmount of an ext3 filesystem.

CVE-2010-0415: The do_pages_move function in mm/migrate.c in the Linux
kernel does not validate node values, which allows local users to read
arbitrary kernel memory locations, cause a denial of service (OOPS),
and possibly have unspecified other impact by specifying a node that
is not part of the kernel's node set.

CVE-2010-0410: drivers/connector/connector.c in the Linux kernel
allows local users to cause a denial of service (memory consumption
and system crash) by sending the kernel many NETLINK_CONNECTOR
messages.

CVE-2009-4031: The do_insn_fetch function in arch/x86/kvm/emulate.c in
the x86 emulator in the KVM subsystem in the Linux kernel tries to
interpret instructions that contain too many bytes to be valid, which
allows guest OS users to cause a denial of service (increased
scheduling latency) on the host OS via unspecified manipulations
related to SMP support.

This update also contains a large rollup of fixes for the rt2860 and
rt3090 wireless drivers from the mainline kernel."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=474773"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=544760"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=555747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=558269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=561078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=565962"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=566634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=568319"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=570314"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=574654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=577747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=577753"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578222"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578550"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=578708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=579076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=579219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=579439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=579989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=580799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=581271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=581718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=582552"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=582907"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=584320"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-desktop-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-trace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:preload-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/23");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-base-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-debug-devel-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-base-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-default-devel-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-base-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-desktop-devel-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-base-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-pae-devel-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-source-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-source-vanilla-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-syms-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-base-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-trace-devel-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-base-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-vanilla-devel-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-base-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"kernel-xen-devel-2.6.31.12-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-default-1.1_2.6.31.12_0.2-6.9.15") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"preload-kmp-desktop-1.1_2.6.31.12_0.2-6.9.15") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-debug-base / kernel-debug-devel / etc");
}
