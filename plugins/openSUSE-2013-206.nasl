#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2013-206.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(74922);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:09:12 $");

  script_cve_id("CVE-2013-0787");

  script_name(english:"openSUSE Security Update : MozillaFirefox (openSUSE-SU-2013:0467-1)");
  script_summary(english:"Check for the openSUSE-2013-206 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 19.0.2 (bnc#808243) fixing :

  - MFSA 2013-29/CVE-2013-0787 (bmo#848644) Use-after-free
    in HTML Editor could be used for code execution

  - blocklist updates"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2013-03/msg00053.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=808243"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/09");
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
if (release !~ "^(SUSE12\.1|SUSE12\.2|SUSE12\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.1 / 12.2 / 12.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-branding-upstream-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-buildsymbols-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debuginfo-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-debugsource-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-devel-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-common-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.1", reference:"MozillaFirefox-translations-other-19.0.2-2.66.1") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-branding-upstream-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-buildsymbols-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debuginfo-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-debugsource-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-devel-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-common-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.2", reference:"MozillaFirefox-translations-other-19.0.2-2.37.2") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-19.0.2-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-branding-upstream-19.0.2-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-buildsymbols-19.0.2-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debuginfo-19.0.2-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-debugsource-19.0.2-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-devel-19.0.2-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-common-19.0.2-1.4.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"MozillaFirefox-translations-other-19.0.2-1.4.1") ) flag++;

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
