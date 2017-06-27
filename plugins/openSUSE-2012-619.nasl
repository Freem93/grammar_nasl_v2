#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-619.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74759);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 20:53:55 $");

  script_cve_id("CVE-2012-2865", "CVE-2012-2866", "CVE-2012-2867", "CVE-2012-2868", "CVE-2012-2869", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2872");
  script_osvdb_id(85030, 85031, 85032, 85033, 85034, 85035, 85036, 85037, 91608);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2012:1215-1)");
  script_summary(english:"Check for the openSUSE-2012-619 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was updated to 21.0.1180.88 to fix various bugs and security
issues. Security fixes and rewards :

Please see the Chromium security
page<http://sites.google.com/a/chromium.org/dev/Home/chromium-security
>for more detail. Note that the referenced bugs may be kept private
until a majority of our users are up to date with the fix.

  - [$500]
    [121347<https://code.google.com/p/chromium/issues/detail
    ?id=121347>] Medium CVE-2012-2865: Out-of-bounds read in
    line breaking. Credit to miaubiz.

  - [$1000]
    [134897<https://code.google.com/p/chromium/issues/detail
    ?id=134897>] High CVE-2012-2866: Bad cast with run-ins.
    Credit to miaubiz.

  - [135485
    <https://code.google.com/p/chromium/issues/detail?id=135
    485>] Low CVE-2012-2867: Browser crash with SPDY.

  - [$500]
    [136881<https://code.google.com/p/chromium/issues/detail
    ?id=136881>] Medium CVE-2012-2868: Race condition with
    workers and XHR. Credit to miaubiz.

  - [137778
    <https://code.google.com/p/chromium/issues/detail?id=137
    778>] High CVE-2012-2869: Avoid stale buffer in URL
    loading. Credit to Fermin Serna of the Google Security
    Team.

  - [138672
    <https://code.google.com/p/chromium/issues/detail?id=138
    672>] [ 140368
    <https://code.google.com/p/chromium/issues/detail?id=140
    368>] LowCVE-2012-2870: Lower severity memory management
    issues in XPath. Credit to Nicolas Gregoire.

  - [$1000]
    [138673<https://code.google.com/p/chromium/issues/detail
    ?id=138673>] High CVE-2012-2871: Bad cast in XSL
    transforms. Credit to Nicolas Gregoire.

  - [$500]
    [142956<https://code.google.com/p/chromium/issues/detail
    ?id=142956>] Medium CVE-2012-2872: XSS in SSL
    interstitial. Credit to Emmanuel Bronshtein."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-09/msg00080.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://sites.google.com/a/chromium.org/dev/Home/chromium-security"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=778005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=121347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=134897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=135485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=136881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=137778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=138672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=138673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=140368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://code.google.com/p/chromium/issues/detail?id=142956"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromedriver-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-desktop-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/10");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-debuginfo-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-23.0.1255.0-1.34.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-debuginfo-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debuginfo-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debugsource-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-gnome-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-kde-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-23.0.1255.0-1.14.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-debuginfo-23.0.1255.0-1.14.1") ) flag++;

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
