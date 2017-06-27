#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaThunderbird-5050.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75966);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/06/16 11:00:59 $");

  script_cve_id("CVE-2011-0084", "CVE-2011-2378", "CVE-2011-2980", "CVE-2011-2981", "CVE-2011-2982", "CVE-2011-2983", "CVE-2011-2984");

  script_name(english:"openSUSE Security Update : MozillaThunderbird (MozillaThunderbird-5050)");
  script_summary(english:"Check for the MozillaThunderbird-5050 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to 3.1.12 fixing various bugs and
security issues :

Mozilla Foundation Security Advisory 2011-32 (MFSA 2011-32)
http://www.mozilla.org/security/announce/2011/mfsa2011-32.html

Many of the issues listed below are not exploitable through mail since
JavaScript is disabled by default in Thunderbird. These particular
issues may be triggered while viewing RSS feeds and displaying full
remote content rather than the feed summary. Addons that expose
browser functionality may also enable such issues to be exploited.

dbg114-MozillaThunderbird-5050 MozillaThunderbird-5050 new_updateinfo
Miscellaneous memory safety hazards (rv:1.9.2.20)

Mozilla developers and community members identified and fixed several
memory safety bugs in the browser engine used in Thunderbird 3.1 and
other Mozilla-based products. Some of these bugs showed evidence of
memory corruption under certain circumstances, and we presume that
with enough effort at least some of these could be exploited to run
arbitrary code.

Gary Kwong, Igor Bukanov, Nils and Bob Clary reported memory safety
issues which affected Thunderbird 3.1. (CVE-2011-2982)

dbg114-MozillaThunderbird-5050 MozillaThunderbird-5050 new_updateinfo
Crash in SVGTextElement.getCharNumAtPosition()

Security researcher regenrecht reported via TippingPoint's Zero Day
Initiative that a SVG text manipulation routine contained a dangling
pointer vulnerability. (CVE-2011-0084)

dbg114-MozillaThunderbird-5050 MozillaThunderbird-5050 new_updateinfo
Privilege escalation using event handlers

Mozilla security researcher moz_bug_r_a_4 reported a vulnerability in
event management code that would permit JavaScript to be run in the
wrong context, including that of a different website or potentially in
a chrome-privileged context. (CVE-2011-2981)

dbg114-MozillaThunderbird-5050 MozillaThunderbird-5050 new_updateinfo
Dangling pointer vulnerability in appendChild

Security researcher regenrecht reported via TippingPoint's Zero Day
Initiative that appendChild did not correctly account for DOM objects
it operated upon and could be exploited to dereference an invalid
pointer. (CVE-2011-2378)

dbg114-MozillaThunderbird-5050 MozillaThunderbird-5050 new_updateinfo
Privilege escalation dropping a tab element in content area

Mozilla security researcher moz_bug_r_a4 reported that web content
could receive chrome privileges if it registered for drop events and a
browser tab element was dropped into the content area. (CVE-2011-2984)

dbg114-MozillaThunderbird-5050 MozillaThunderbird-5050 new_updateinfo
Binary planting vulnerability in ThinkPadSensor::Startup

Security researcher Mitja Kolsek of Acros Security reported that
ThinkPadSensor::Startup could potentially be exploited to load a
malicious DLL into the running process. (CVE-2011-2980)

dbg114-MozillaThunderbird-5050 MozillaThunderbird-5050 new_updateinfo
Private data leakage using RegExp.input

Security researcher shutdown reported that data from other domains
could be read when RegExp.input was set. (CVE-2011-2983)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2011/mfsa2011-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=712224"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaThunderbird packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-772");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/26");
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

if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-buildsymbols-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debuginfo-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-debugsource-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-devel-debuginfo-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-common-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaThunderbird-translations-other-3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-1.1.2+3.1.12-0.11.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"enigmail-debuginfo-1.1.2+3.1.12-0.11.1") ) flag++;

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
