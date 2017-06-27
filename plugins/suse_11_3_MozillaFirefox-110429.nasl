#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-4459.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75652);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/13 21:55:23 $");

  script_cve_id("CVE-2011-0065", "CVE-2011-0066", "CVE-2011-0067", "CVE-2011-0069", "CVE-2011-0070", "CVE-2011-0071", "CVE-2011-0072", "CVE-2011-0073", "CVE-2011-0074", "CVE-2011-0075", "CVE-2011-0076", "CVE-2011-0077", "CVE-2011-0078", "CVE-2011-0080", "CVE-2011-0081", "CVE-2011-1202");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-4459)");
  script_summary(english:"Check for the MozillaFirefox-4459 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 3.6.17 security release.

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
3.6 and Firefox 3.5. (CVE-2011-0072)

MFSA 2011-13 / CVE-2011-0065 / CVE-2011-0066 / CVE-2011-0073: Security
researcher regenrecht reported several dangling pointer
vulnerabilities via TippingPoint's Zero Day Initiative.

MFSA 2011-14 / CVE-2011-0067: Security researcher Paul Stone reported
that a Java applet could be used to mimic interaction with form
autocomplete controls and steal entries from the form history.

MFSA 2011-15 / CVE-2011-0076: David Remahl of Apple Product Security
reported that the Java Embedding Plugin (JEP) shipped with the Mac OS
X versions of Firefox could be exploited to obtain elevated access to
resources on a user's system.

MFSA 2011-16 / CVE-2011-0071: Security researcher Soroush Dalili
reported that the resource: protocol could be exploited to allow
directory traversal on Windows and the potential loading of resources
from non-permitted locations. The impact would depend on whether
interesting files existed in predictable locations in a useful format.
For example, the existence or non-existence of particular images might
indicate whether certain software was installed. 

MFSA 2011-18 / CVE-2011-1202: Chris Evans of the Chrome Security Team
reported that the XSLT generate-id() function returned a string that
revealed a specific valid address of an object on the memory heap. It
is possible that in some cases this address would be valuable
information that could be used by an attacker while exploiting a
different memory corruption but, in order to make an exploit more
reliable or work around mitigation features in the browser or
operating system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=689281"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox "nsTreeRange" Dangling Pointer Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
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
if (release !~ "^(SUSE11\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-3.6.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-branding-upstream-3.6.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-common-3.6.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"MozillaFirefox-translations-other-3.6.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-js192-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-buildsymbols-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-devel-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-gnome-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-common-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", reference:"mozilla-xulrunner192-translations-other-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-js192-32bit-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-common-32bit-1.9.2.17-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.3", cpu:"x86_64", reference:"mozilla-xulrunner192-translations-other-32bit-1.9.2.17-0.2.1") ) flag++;

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
