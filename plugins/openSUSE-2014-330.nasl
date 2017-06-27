#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-330.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75340);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:39:49 $");

  script_cve_id("CVE-2014-1716", "CVE-2014-1717", "CVE-2014-1718", "CVE-2014-1719", "CVE-2014-1720", "CVE-2014-1721", "CVE-2014-1722", "CVE-2014-1723", "CVE-2014-1724", "CVE-2014-1725", "CVE-2014-1726", "CVE-2014-1727", "CVE-2014-1728", "CVE-2014-1729");
  script_bugtraq_id(66704);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:0601-1)");
  script_summary(english:"Check for the openSUSE-2014-330 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This chromium version update fixes the following security and
non-security issues :

  - Add patch chromium-fix-arm-skia-memset.patch to resolve
    a linking issue on ARM with regards to missing symbols.

  - Add patch arm_use_gold.patch to use the right gold
    binaries on ARM. Hopefully this resolves the build
    issues with running out of memory

  - bnc#872805: Update to Chromium 34.0.1847.116

  - Responsive Images and Unprefixed Web Audio

  - Import supervised users onto new computers

  - A number of new apps/extension APIs 

  - Lots of under the hood changes for stability and
    performance 

  - Security fixes :

  - CVE-2014-1716: UXSS in V8

  - CVE-2014-1717: OOB access in V8

  - CVE-2014-1718: Integer overflow in compositor

  - CVE-2014-1719: Use-after-free in web workers

  - CVE-2014-1720: Use-after-free in DOM

  - CVE-2014-1721: Memory corruption in V8

  - CVE-2014-1722: Use-after-free in rendering

  - CVE-2014-1723: Url confusion with RTL characters

  - CVE-2014-1724: Use-after-free in speech

  - CVE-2014-1725: OOB read with window property

  - CVE-2014-1726: Local cross-origin bypass

  - CVE-2014-1727: Use-after-free in forms

  - CVE-2014-1728: Various fixes from internal audits,
    fuzzing and other initiatives

  - CVE-2014-1729: Multiple vulnerabilities in V8 

  - No longer build against system libraries as that
    Chromium works a lot better and crashes less on websites
    than with system libs

  - Added package depot_tools.tar.gz as that the chromium
    build now requires it during the initial build phase. It
    just contains some utilities and nothing from it is
    being installed.

  - If people want to install newer versions of the ffmpeg
    library then let them. This is what they want.

  - Remove the buildscript from the sources"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=872805"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-ffmpegsumo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/22");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-debuginfo-34.0.1847.116-1.37.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-34.0.1847.116-29.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-debuginfo-34.0.1847.116-29.3") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromedriver / chromedriver-debuginfo / chromium / etc");
}
