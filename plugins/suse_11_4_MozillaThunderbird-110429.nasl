#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-4458.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75964);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 22:10:33 $");

  script_cve_id("CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0072", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (MozillaThunderbird-4458)");
  script_summary(english:"Check for the MozillaThunderbird-4458 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to the 3.1.10 security release.

MFSA 2011-12: Mozilla developers identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code. Credits

Mozilla developer Scoobidiver reported a memory safety issue which
affected Firefox 4 and Firefox 3.6 (CVE-2011-0081)

The web development team of Alcidion reported a crash that affected
Firefox 4, Firefox 3.6 and Firefox 3.5. (CVE-2011-0069)

Ian Beer reported a crash that affected Firefox 4, Firefox 3.6 and
Firefox 3.5. (CVE-2011-0070)

Mozilla developers Bob Clary, Henri Sivonen, Marco Bonardo, Mats
Palmgren and Jesse Ruderman reported memory safety issues which
affected Firefox 3.6 and Firefox 3.5. (CVE-2011-0080)

Aki Helin reported memory safety issues which affected Firefox 3.6 and
Firefox 3.5. (CVE-2011-0074 , CVE-2011-0075)

Ian Beer reported memory safety issues which affected Firefox 3.6 and
Firefox 3.5. (CVE-2011-0077 , CVE-2011-0078)

Martin Barbella reported a memory safety issue which affected Firefox
3.6 and Firefox 3.5. (CVE-2011-0072)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689281"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-buildsymbols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaThunderbird-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:enigmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/29");
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

if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-debuginfo-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-3.1.10-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.1.2-9.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.1.2-9.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaThunderbird");
}
