#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2012-721.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74788);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2012-2874", "CVE-2012-2876", "CVE-2012-2877", "CVE-2012-2878", "CVE-2012-2879", "CVE-2012-2880", "CVE-2012-2881", "CVE-2012-2882", "CVE-2012-2883", "CVE-2012-2884", "CVE-2012-2885", "CVE-2012-2886", "CVE-2012-2887", "CVE-2012-2888", "CVE-2012-2889", "CVE-2012-2891", "CVE-2012-2892", "CVE-2012-2893", "CVE-2012-2894", "CVE-2012-2896");
  script_bugtraq_id(55676);
  script_osvdb_id(85751, 85752, 85753, 85755, 85756, 85757, 85759, 85760, 85761, 85762, 85763, 85764, 85765, 85766, 85767, 85768, 85769, 85770, 85771, 85775);

  script_name(english:"openSUSE Security Update : chromium (openSUSE-SU-2012:1376-1)");
  script_summary(english:"Check for the openSUSE-2012-721 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chromium was upgraded to version 24.0.1290 which fixed multiple
security flaws."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2012-10/msg00066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=782257"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:chromium-suid-helper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/12");
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

if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromedriver-debuginfo-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debuginfo-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-debugsource-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-gnome-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-desktop-kde-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"chromium-suid-helper-debuginfo-24.0.1290.0-1.39.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromedriver-debuginfo-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debuginfo-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-debugsource-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-gnome-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-desktop-kde-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-24.0.1290.0-1.19.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"chromium-suid-helper-debuginfo-24.0.1290.0-1.19.1") ) flag++;

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
