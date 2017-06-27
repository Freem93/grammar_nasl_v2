#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-565.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(85834);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/09/26 18:46:52 $");

  script_cve_id("CVE-2015-4497", "CVE-2015-4498");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-2015-565)");
  script_summary(english:"Check for the openSUSE-2015-565 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox was updated to version 40.0.3 to fix two security
issues and several bugs.

Changes in MozillaFirefox :

  - update to Firefox 40.0.3 (bnc#943550)

  - Disable the asynchronous plugin initialization
    (bmo#1198590)

  - Fix a segmentation fault in the GStreamer support
    (bmo#1145230)

  - Fix a regression with some Japanese fonts used in the
    <input> field (bmo#1194055)

  - On some sites, the selection in a select combox box
    using the mouse could be broken (bmo#1194733) security
    fixes

  - MFSA 2015-94/CVE-2015-4497 (bmo#1164766, bmo#1175278,
    bsc#943557) Use-after-free when resizing canvas element
    during restyling

  - MFSA 2015-95/CVE-2015-4498 (bmo#1042699, bsc#943558)
    Add-on notification bypass through data URLs"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=943550"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");
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

if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-branding-upstream-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-buildsymbols-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debuginfo-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-debugsource-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-devel-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-common-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaFirefox-translations-other-40.0.3-85.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-40.0.3-41.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-branding-upstream-40.0.3-41.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-buildsymbols-40.0.3-41.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debuginfo-40.0.3-41.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-debugsource-40.0.3-41.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-devel-40.0.3-41.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-common-40.0.3-41.2") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaFirefox-translations-other-40.0.3-41.2") ) flag++;

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
