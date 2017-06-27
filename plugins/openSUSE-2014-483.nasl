#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-483.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(77127);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/08/21 13:58:51 $");

  script_cve_id("CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3156", "CVE-2014-3157", "CVE-2014-3160", "CVE-2014-3162");
  script_bugtraq_id(67972, 67977, 67980, 67981, 68677);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:0982-1)");
  script_summary(english:"Check for the openSUSE-2014-483 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to version 36.0.1985.125. New Functionality :

  - Rich Notifications Improvements

  - An Updated Incognito / Guest NTP design

  - The addition of a Browser crash recovery bubble

  - Chrome App Launcher for Linux

  - Lots of under the hood changes for stability and
    performance Security Fixes (bnc#887952,bnc#887955) :

  - CVE-2014-3160: Same-Origin-Policy bypass in SVG

  - CVE-2014-3162: Various fixes from internal audits,
    fuzzing and other initiatives and 24 more fixes for
    which no description was given. Packaging changes :

  - Switch to newer method to retrieve toolchain packages.
    Dropping the three naclsdk_*tgz files. Everything is now
    included in the toolchain_linux_x86.tar.bz2 tarball

  - Add Courgette.tar.xz as that the build process now
    requires some files from Courgette in order to build
    succesfully. This does not mean that Courgette is
    build/delivered.

Includes also an update to Chromium 35.0.1916.153 Security fixes
(bnc#882264,bnc#882264,bnc#882265,bnc#882263) :

  - CVE-2014-3154: Use-after-free in filesystem api

  - CVE-2014-3155: Out-of-bounds read in SPDY

  - CVE-2014-3156: Buffer overflow in clipboard

  - CVE-2014-3157: Heap overflow in media"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-08/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=882265"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887952"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=887955"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");
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

if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-debuginfo-36.0.1985.125-1.50.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-36.0.1985.125-41.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-debuginfo-36.0.1985.125-41.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
