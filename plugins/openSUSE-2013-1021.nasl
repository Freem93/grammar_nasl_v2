#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-1021.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74865);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-1442", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4369", "CVE-2013-4370", "CVE-2013-4371", "CVE-2013-4375", "CVE-2013-4416");
  script_osvdb_id(97770, 97954, 97955, 98287, 98288, 98289, 98290, 98332, 99072);

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2013:1953-1)");
  script_summary(english:"Check for the openSUSE-2013-1021 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to 4.2.3 c/s 26170 to fix various bugs and security
issues.

Following issues were fixed :

  - bnc#845520 - CVE-2013-4416: xen: ocaml xenstored
    mishandles oversized message replies

  - bnc#833483 - Boot Failure with xen kernel in UEFI mode
    with error 'No memory for trampoline'

  - Improvements to block-dmmd script bnc#828623

  - bnc#840196 - MTU size on Dom0 gets reset when booting
    DomU with e1000 device

  - bnc#840592 - CVE-2013-4355: XSA-63: xen: Information
    leaks through I/O instruction emulation

  - bnc#841766 - CVE-2013-4361: XSA-66: xen: Information
    leak through fbld instruction emulation

  - bnc#842511 - CVE-2013-4368: XSA-67: xen: Information
    leak through outs instruction emulation

  - bnc#842512 - CVE-2013-4369: XSA-68: xen: possible null
    dereference when parsing vif ratelimiting info

  - bnc#842513 - CVE-2013-4370: XSA-69: xen: misplaced free
    in ocaml xc_vcpu_getaffinity stub

  - bnc#842514 - CVE-2013-4371: XSA-70: xen: use-after-free
    in libxl_list_cpupool under memory pressure

  - bnc#842515 - CVE-2013-4375: XSA-71: xen: qemu disk
    backend (qdisk) resource leak

  - bnc#839596 - CVE-2013-1442: XSA-62: xen: Information
    leak on AVX and/or LWP capable CPUs

  - bnc#833251 - [HP BCS SLES11 Bug]: In HP&rsquo;s UEFI
    x86_64 platform and with xen environment, in booting
    stage ,xen hypervisor will panic.

  - bnc#833796 - Xen: migration broken from xsave-capable to
    xsave-incapable host

  - bnc#834751 - [HP BCS SLES11 Bug]: In xen,
    &ldquo;shutdown &ndash;y 0 &ndash;h&rdquo; cannot power
    off system

  - bnc#839600 - [HP BCS SLES11 Bug]: In HP&rsquo;s UEFI
    x86_64 platform and sles11sp3 with xen environment, xen
    hypervisor will panic on multiple blades nPar. 

  - bnc#833251 - [HP BCS SLES11 Bug]: In HP&rsquo;s UEFI
    x86_64 platform and with xen environment, in booting
    stage ,xen hypervisor will panic.

  - bnc#835896 - vcpus not started after upgrading Dom0 from
    11SP2 to SP3

  - bnc#836239 - SLES 11 SP3 Xen security patch does not
    automatically update UEFI boot binary"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-12/msg00115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=828623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=835896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=836239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839596"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=839600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=840592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=841766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=842515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845520"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/05");
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
if (release !~ "^(SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"xen-debugsource-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-devel-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-4.2.3_01_k3.7.10_1.16-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-default-debuginfo-4.2.3_01_k3.7.10_1.16-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-4.2.3_01_k3.7.10_1.16-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-desktop-debuginfo-4.2.3_01_k3.7.10_1.16-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-4.2.3_01_k3.7.10_1.16-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-kmp-pae-debuginfo-4.2.3_01_k3.7.10_1.16-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-libs-debuginfo-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xen-tools-domU-debuginfo-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-html-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-doc-pdf-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-32bit-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-4.2.3_01-1.22.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", cpu:"x86_64", reference:"xen-tools-debuginfo-4.2.3_01-1.22.4") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen");
}
