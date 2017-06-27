#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-420.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75387);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/12/05 14:24:35 $");

  script_cve_id("CVE-2014-1740", "CVE-2014-1741", "CVE-2014-1742", "CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746", "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3152");
  script_bugtraq_id(67374, 67375, 67376, 67517, 71464);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2014:0783-1)");
  script_summary(english:"Check for the openSUSE-2014-420 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"chromium was updated to version 35.0.1916.114 to fix various security
issues. Security fixes :

  - CVE-2014-1743: Use-after-free in styles

  - CVE-2014-1744: Integer overflow in audio

  - CVE-2014-1745: Use-after-free in SVG

  - CVE-2014-1746: Out-of-bounds read in media filters

  - CVE-2014-1747: UXSS with local MHTML file

  - CVE-2014-1748: UI spoofing with scrollbar

  - CVE-2014-1749: Various fixes from internal audits,
    fuzzing and other initiatives

  - CVE-2014-3152: Integer underflow in V8 fixed

  - CVE-2014-1740: Use-after-free in WebSockets

  - CVE-2014-1741: Integer overflow in DOM range

  - CVE-2014-1742: Use-after-free in editing and 17 more for
    which no detailed information is given."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-06/msg00023.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ninja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ninja-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ninja-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
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

if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromedriver-debuginfo-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debuginfo-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-debugsource-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-gnome-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-desktop-kde-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-ffmpegsumo-debuginfo-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"chromium-suid-helper-debuginfo-35.0.1916.114-1.45.4") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ninja-3.0+git.20130603.0f53fd3-2.6.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ninja-debuginfo-3.0+git.20130603.0f53fd3-2.6.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"ninja-debugsource-3.0+git.20130603.0f53fd3-2.6.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromedriver-debuginfo-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debuginfo-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-debugsource-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-gnome-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-desktop-kde-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-ffmpegsumo-debuginfo-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-35.0.1916.114-37.4") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"chromium-suid-helper-debuginfo-35.0.1916.114-37.4") ) flag++;

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
