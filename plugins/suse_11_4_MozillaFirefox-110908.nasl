#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-5119.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75946);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2011:1031-1)");
  script_summary(english:"Check for the MozillaFirefox-5119 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to 6.0.2.

The purpose of this update is to blacklist the compromised DigiNotar
Certificate Authority.

For more information read: MFSA 2011-34
http://www.mozilla.org/security/announce/2011/mfsa2011-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-09/msg00017.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714931"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/08");
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
if (release !~ "^(SUSE11\.4)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.4", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-6.0.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-6.0.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-buildsymbols-6.0.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-6.0.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-6.0.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-6.0.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-6.0.2-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-6.0.2-0.2.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
