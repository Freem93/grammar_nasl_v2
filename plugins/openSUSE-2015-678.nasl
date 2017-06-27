#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-678.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(86595);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/11/08 16:01:24 $");

  script_cve_id("CVE-2015-7184");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2015-678)");
  script_summary(english:"Check for the openSUSE-2015-678 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to version 41.0.2 to fix one security
issue.

This security issue was fixed :

  - CVE-2015-7184: Cross-origin restriction bypass using
    Fetch (bsc#950686).

These non-security issues were fixed :

  - Fix a startup crash related to Yandex toolbar and
    Adblock Plus (bmo#1209124)

  - Fix potential hangs with Flash plugins (bmo#1185639)

  - Fix a regression in the bookmark creation (bmo#1206376)

  - Fix a startup crash with some Intel Media Accelerator
    3150 graphic cards (bmo#1207665)

  - Fix a graphic crash, occurring occasionally on Facebook
    (bmo#1178601)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=949983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=950686"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE13\.1|SUSE13\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1 / 13.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-41.0.2-91.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-41.0.2-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-41.0.2-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-41.0.2-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-41.0.2-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-41.0.2-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-41.0.2-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-41.0.2-47.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-41.0.2-47.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-upstream / etc");
}
