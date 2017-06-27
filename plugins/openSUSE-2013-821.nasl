#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-821.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75189);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:24:48 $");

  script_cve_id("CVE-2013-1442", "CVE-2013-4355", "CVE-2013-4361", "CVE-2013-4368", "CVE-2013-4416");
  script_bugtraq_id(62630, 62708, 62710, 62935, 63404);
  script_osvdb_id(97770, 97954, 97955, 98290, 99072);

  script_name(english:"openSUSE Security Update : xen (openSUSE-SU-2013:1636-1)");
  script_summary(english:"Check for the openSUSE-2013-821 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xen was updated to 4.1.6 c/s 23588 to fix various bugs and security
issues.

Following changes are listed :

  - Comment out the -include directive in Config.mk as the
    build service build seems to error out not finding
    '.config' xen-config.diff

  - bnc#845520 - CVE-2013-4416: xen: ocaml xenstored
    mishandles oversized message replies

  - Improvements to block-dmmd script bnc#828623

  - bnc#840196 - MTU size on Dom0 gets reset when booting
    DomU with e1000 device

  - bnc#840592 - CVE-2013-4355: XSA-63: xen: Information
    leaks through I/O instruction emulation

  - bnc#841766 - CVE-2013-4361: XSA-66: xen: Information
    leak through fbld instruction emulation

  - bnc#842511 - CVE-2013-4368: XSA-67: xen: Information
    leak through outs instruction emulation

  - xen/27397-ACPI-fix-acpi_os_map_memory.patch: address
    regression

  - bnc#839596 - CVE-2013-1442: XSA-62: xen: Information
    leak on AVX and/or LWP capable CPUs

  - bnc#833251 - In HP&rsquo;s UEFI x86_64 platform and with
    xen environment, in booting stage ,xen hypervisor will
    panic.

  - bnc#833796 - Xen: migration broken from xsave-capable to
    xsave-incapable host

  - bnc#834751 - In xen, &ldquo;shutdown &ndash;y 0
    &ndash;h&rdquo; cannot power off system

  - bnc#833251 - In HP&rsquo;s UEFI x86_64 platform and with
    xen environment, in booting stage ,xen hypervisor will
    panic.

  - bnc#839600 - In HP&rsquo;s UEFI x86_64 platform and
    sles11sp3 with xen environment, xen hypervisor will
    panic on multiple blades nPar."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-11/msg00009.html"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=833796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=834751"
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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=845520"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/30");
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

if ( rpm_check(release:"SUSE12.2", reference:"xen-debugsource-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-devel-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-4.1.6_01_k3.4.47_2.38-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-default-debuginfo-4.1.6_01_k3.4.47_2.38-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-4.1.6_01_k3.4.47_2.38-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-desktop-debuginfo-4.1.6_01_k3.4.47_2.38-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-4.1.6_01_k3.4.47_2.38-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-kmp-pae-debuginfo-4.1.6_01_k3.4.47_2.38-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-libs-debuginfo-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"xen-tools-domU-debuginfo-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-html-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-doc-pdf-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-32bit-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-libs-debuginfo-32bit-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-4.1.6_01-5.33.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", cpu:"x86_64", reference:"xen-tools-debuginfo-4.1.6_01-5.33.1") ) flag++;

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
