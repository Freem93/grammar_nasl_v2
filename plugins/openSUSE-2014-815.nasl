#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-815.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80275);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/29 13:38:34 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2014-8103");

  script_name(english:"openSUSE Security Update : xorg-x11-server (openSUSE-SU-2014:1719-1)");
  script_summary(english:"Check for the openSUSE-2014-815 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This X.Org update fixes the following security and non security 
issues :

  - Add and update security patches. (bnc#907268,
    CVE-2014-8091, CVE-2014-8092, CVE-2014-8093,
    CVE-2014-8094, CVE-2014-8095, CVE-2014-8096,
    CVE-2014-8097, CVE-2014-8098, CVE-2014-8099,
    CVE-2014-8100, CVE-2014-8101, CVE-2014-8102,
    CVE-2014-8103)
    http://lists.x.org/archives/xorg-announce/2014-December/
    002501.html

  - Fixes rendering of some icewm and xfwm themes.
    (bnc#908258, bnc#856931)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00103.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.x.org/archives/xorg-announce/2014-December/002501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=856931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=907268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908258"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:xorg-x11-server-sdk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/29");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-7.6_1.13.2-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-debuginfo-7.6_1.13.2-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-debugsource-7.6_1.13.2-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-extra-7.6_1.13.2-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-extra-debuginfo-7.6_1.13.2-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"xorg-x11-server-sdk-7.6_1.13.2-1.29.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xorg-x11-server-7.6_1.14.3.901-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xorg-x11-server-debuginfo-7.6_1.14.3.901-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xorg-x11-server-debugsource-7.6_1.14.3.901-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xorg-x11-server-extra-7.6_1.14.3.901-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xorg-x11-server-extra-debuginfo-7.6_1.14.3.901-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"xorg-x11-server-sdk-7.6_1.14.3.901-12.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xorg-x11-server-7.6_1.16.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xorg-x11-server-debuginfo-7.6_1.16.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xorg-x11-server-debugsource-7.6_1.16.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xorg-x11-server-extra-7.6_1.16.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xorg-x11-server-extra-debuginfo-7.6_1.16.1-5.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"xorg-x11-server-sdk-7.6_1.16.1-5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server / xorg-x11-server-debuginfo / etc");
}
