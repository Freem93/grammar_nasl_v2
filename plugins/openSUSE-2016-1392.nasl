#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1392.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(95552);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2017/01/24 14:51:33 $");

  script_cve_id("CVE-2016-9078", "CVE-2016-9079");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2016-1392)");
  script_summary(english:"Check for the openSUSE-2016-1392 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox is updated to version 50.0.2 which fixes the following
issues :

  - Firefox crashed with 3rd party Chinese IME when using
    IME text (fixed in version 50.0.1)

  - Redirection from an HTTP connection to a data: URL could
    inherit wrong origin after an HTTP redirect (fixed in
    version 50.0.1, bmo#1317641, MFSA 2016-91, boo#1012807,
    CVE-2016-9078)

  - Maliciously crafted SVG animations could cause remote
    code execution (fixed in version 50.0.2, bmo#1321066,
    MFSA 2016-92, boo##1012964, CVE-2016-9079)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012807"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012964"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox nsSMILTimeContainer::NotifyTimeChange() RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.2|SUSE42\.1|SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.2 / 42.1 / 42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-50.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-branding-upstream-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-buildsymbols-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debuginfo-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-debugsource-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-devel-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-common-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.1", cpu:"x86_64", reference:"MozillaFirefox-translations-other-50.0.2-42.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-50.0.2-42.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-branding-upstream-50.0.2-42.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-buildsymbols-50.0.2-42.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debuginfo-50.0.2-42.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-debugsource-50.0.2-42.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-devel-50.0.2-42.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-common-50.0.2-42.2") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"MozillaFirefox-translations-other-50.0.2-42.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
