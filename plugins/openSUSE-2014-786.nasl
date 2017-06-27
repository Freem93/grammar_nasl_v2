#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-786.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80095);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/18 05:41:18 $");

  script_cve_id("CVE-2014-1587", "CVE-2014-1590", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2014:1654-1)");
  script_summary(english:"Check for the openSUSE-2014-786 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This MozillaThunderbird update fixes several security and non security
issues :

Changes in MozillaThunderbird :

  - update to Thunderbird 31.3.0 (bnc#908009)

  - MFSA 2014-83/CVE-2014-1587 Miscellaneous memory safety
    hazards

  - MFSA 2014-85/CVE-2014-1590 (bmo#1087633) XMLHttpRequest
    crashes with some input streams

  - MFSA 2014-87/CVE-2014-1592 (bmo#1088635) Use-after-free
    during HTML5 parsing

  - MFSA 2014-88/CVE-2014-1593 (bmo#1085175) Buffer overflow
    while parsing media content

  - MFSA 2014-89/CVE-2014-1594 (bmo#1074280) Bad casting
    from the BasicThebesLayer to BasicContainerLayer

  - fix bashism in mozilla.sh script

  - Limit RAM usage during link for ARM

  - remove add-plugins.sh and use /usr/share/myspell
    directly (bnc#900639)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-12/msg00067.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=900639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=908009"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-31.3.0-61.67.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-buildsymbols-31.3.0-61.67.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debuginfo-31.3.0-61.67.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-debugsource-31.3.0-61.67.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-devel-31.3.0-61.67.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-common-31.3.0-61.67.3") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaThunderbird-translations-other-31.3.0-61.67.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-31.3.0-70.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-31.3.0-70.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-31.3.0-70.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-31.3.0-70.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-31.3.0-70.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-31.3.0-70.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-31.3.0-70.39.3") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-31.3.0-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-31.3.0-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-31.3.0-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-31.3.0-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-31.3.0-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-31.3.0-4.4") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-31.3.0-4.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
