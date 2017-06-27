#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-5408.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75657);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-3647", "CVE-2011-3648", "CVE-2011-3650");
  script_osvdb_id(76947, 76948, 76952);

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2011:1242-1)");
  script_summary(english:"Check for the MozillaFirefox-5408 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"MozillaFirefox has been updated to version 3.6.24 to fix the following
security issues :

  - MFSA 2011-46/CVE-2011-3647 (bmo#680880) loadSubScript
    unwraps XPCNativeWrapper scope parameter

  - MFSA 2011-47/CVE-2011-3648 (bmo#690225) Potential XSS
    against sites using Shift-JIS

  - MFSA 2011-49/CVE-2011-3650 (bmo#674776) Memory
    corruption while profiling using Firebug"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-11/msg00014.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=728520"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-openSUSE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-js192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-common-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner192-translations-other-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-3.6.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-branding-openSUSE-3.5-17.3.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-branding-upstream-3.6.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-common-3.6.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-other-3.6.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaThunderbird-3.1.16-0.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaThunderbird-devel-3.1.16-0.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaThunderbird-translations-common-3.1.16-0.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaThunderbird-translations-other-3.1.16-0.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"enigmail-1.1.2+3.1.16-0.23.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-js192-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-devel-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-gnome-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-common-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-other-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.24-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.24-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox / MozillaFirefox-branding-openSUSE / etc");
}
