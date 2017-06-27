#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2015-69.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(80993);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/03/11 13:51:33 $");

  script_cve_id("CVE-2014-8634", "CVE-2014-8635", "CVE-2014-8638", "CVE-2014-8639");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (openSUSE-SU-2015:0133-1)");
  script_summary(english:"Check for the openSUSE-2015-69 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaThunderbird was updated to Thunderbird 31.4.0 (bnc#910669)

  - MFSA 2015-01/CVE-2014-8634/CVE-2014-8635 Miscellaneous
    memory safety hazards

  - MFSA 2015-03/CVE-2014-8638 (bmo#1080987) sendBeacon
    requests lack an Origin header

  - MFSA 2015-04/CVE-2014-8639 (bmo#1095859) Cookie
    injection through Proxy Authenticate responses"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2015-01/msg00071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=910669"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/26");
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

if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-31.4.0-70.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-buildsymbols-31.4.0-70.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debuginfo-31.4.0-70.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-debugsource-31.4.0-70.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-devel-31.4.0-70.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-common-31.4.0-70.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"MozillaThunderbird-translations-other-31.4.0-70.43.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-31.4.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-buildsymbols-31.4.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debuginfo-31.4.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-debugsource-31.4.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-devel-31.4.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-common-31.4.0-8.1") ) flag++;
if ( rpm_check(release:"SUSE13.2", reference:"MozillaThunderbird-translations-other-31.4.0-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird / MozillaThunderbird-buildsymbols / etc");
}
