#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-1000.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(39891);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-1000)");
  script_summary(english:"Check for the MozillaFirefox-1000 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox browser was updated to version 3.0.11, fixing
various bugs and security issues :

  - MFSA 2009-24/CVE-2009-1392/CVE-2009-1832/CVE-2009-1833
    Crashes with evidence of memory corruption (rv:1.9.0.11)

  - MFSA 2009-25/CVE-2009-1834 (bmo#479413) URL spoofing
    with invalid unicode characters

  - MFSA 2009-26/CVE-2009-1835 (bmo#491801) Arbitrary domain
    cookie access by local file: resources

  - MFSA 2009-27/CVE-2009-1836 (bmo#479880) SSL tampering
    via non-200 responses to proxy CONNECT requests

  - MFSA 2009-28/CVE-2009-1837 (bmo#486269) Race condition
    while accessing the private data of a NPObject JS
    wrapper class object

  - MFSA 2009-29/CVE-2009-1838 (bmo#489131) Arbitrary code
    execution using event listeners attached to an element
    whose owner document is null

  - MFSA 2009-30/CVE-2009-1839 (bmo#479943) Incorrect
    principal set for file: resources loaded via location
    bar

  - MFSA 2009-31/CVE-2009-1840 (bmo#477979) XUL scripts
    bypass content-policy checks

  - MFSA 2009-32/CVE-2009-1841 (bmo#479560) JavaScript
    chrome privilege escalation"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=505563"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94, 200, 264, 287, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"MozillaFirefox-3.0.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"MozillaFirefox-translations-3.0.11-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-1.9.0.11-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-devel-1.9.0.11-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.11-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"mozilla-xulrunner190-translations-1.9.0.11-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.11-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.11-1.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.11-1.1") ) flag++;

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
