#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-1774.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44370);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/06/13 20:00:36 $");

  script_cve_id("CVE-2010-0220");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-1774)");
  script_summary(english:"Check for the MozillaFirefox-1774 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was upgraded to 3.5.7 fixing some bugs and
regressions.

CVE-2010-0220: The nsObserverList::FillObserverArray function in
xpcom/ds/nsObserverList.cpp in Mozilla Firefox before 3.5.7 allows
remote attackers to cause a denial of service (application crash) via
a crafted website that triggers memory consumption and an accompanying
Low Memory alert dialog, and also triggers attempted removal of an
observer from an empty observers array."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=568011"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom191");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-3.5.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-branding-upstream-3.5.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-common-3.5.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-other-3.5.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-1.9.1.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-devel-1.9.1.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-common-1.9.1.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-other-1.9.1.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"python-xpcom191-1.9.1.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.7-1.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.7-1.1.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
