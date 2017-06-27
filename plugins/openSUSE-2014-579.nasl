#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-579.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(78116);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/10/10 10:49:10 $");

  script_cve_id("CVE-2013-4344", "CVE-2013-4540", "CVE-2014-2599", "CVE-2014-3967", "CVE-2014-3968", "CVE-2014-4021", "CVE-2014-7154", "CVE-2014-7155", "CVE-2014-7156", "CVE-2014-7188");

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2014:1279-1)");
  script_summary(english:"Check for the openSUSE-2014-579 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"XEN was updated to fix various bugs and security issues.

Security issues fixed :

  - bnc#897657 - CVE-2014-7188: XSA-108 Improper MSR range
    used for x2APIC emulation

  - bnc#895802 - CVE-2014-7156: XSA-106: Missing privilege
    level checks in x86 emulation of software interrupts

  - bnc#895799 - CVE-2014-7155: XSA-105: Missing privilege
    level checks in x86 HLT, LGDT, LIDT, and LMSW emulation

  - bnc#895798 - CVE-2014-7154: XSA-104: Race condition in
    HVMOP_track_dirty_vram

  - bnc#864801 - CVE-2013-4540: qemu: zaurus: buffer overrun
    on invalid state load 

  - bnc#880751 - CVE-2014-4021: XSA-100: Hypervisor heap
    contents leaked to guests

  - bnc#878841 - CVE-2014-3967,CVE-2014-3968: XSA-96:
    Vulnerabilities in HVM MSI injection

  - bnc#867910 - CVE-2014-2599: XSA-89: HVMOP_set_mem_access
    is not preemptible

  - bnc#842006 - CVE-2013-4344: XSA-65: xen: qemu SCSI
    REPORT LUNS buffer overflow

Other bugs fixed :

  - bnc#896023 - Adjust xentop column layout

  - bnc#891539 - xend: fix netif convertToDeviceNumber for
    running domains

  - bnc#820873 - The 'long' option doesn't work with 'xl
    list'

  - bnc#881900 - XEN kernel panic do_device_not_available()

  - bnc#833483 - Boot Failure with xen kernel in UEFI mode
    with error 'No memory for trampoline'

  - bnc#862608 - SLES 11 SP3 vm-install should get RHEL 7
    support when released

  - bnc#858178 - [HP HPS Bug]: SLES11sp3 XEN kiso version
    cause softlockup on 8 blades npar(480 cpu)

  - bnc#865682 - Local attach support for PHY backends using
    scripts

  - bnc#798770 - Improve multipath support for npiv devices"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-10/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=798770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=820873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=858178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=862608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=865682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=867910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=878841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=880751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=881900"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=891539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=895802"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=896023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=897657"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-doc-pdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-desktop-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-kmp-pae-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-libs-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xen-tools-domU-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"xen-debugsource-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-devel-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-4.2.4_04_k3.7.10_1.40-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-debuginfo-4.2.4_04_k3.7.10_1.40-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-4.2.4_04_k3.7.10_1.40-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-debuginfo-4.2.4_04_k3.7.10_1.40-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-4.2.4_04_k3.7.10_1.40-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-debuginfo-4.2.4_04_k3.7.10_1.40-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-debuginfo-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-debuginfo-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-html-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-4.2.4_04-1.32.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-debuginfo-4.2.4_04-1.32.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
