#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-2017.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(44903);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-1571", "CVE-2009-3988", "CVE-2010-0159", "CVE-2010-0160", "CVE-2010-0162");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-2017)");
  script_summary(english:"Check for the MozillaFirefox-2017 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was upgraded to version 3.5.8, fixing various bugs and
security issues.

Following security issues have been fixed: MFSA 2010-01 /
CVE-2010-0159: Mozilla developers identified and fixed several
stability bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these crashes showed evidence of
memory corruption under certain circumstances and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

MFSA 2010-02 / CVE-2010-0160: Security researcher Orlando Barrera II
reported via TippingPoint's Zero Day Initiative that Mozilla's
implementation of Web Workers contained an error in its handling of
array data types when processing posted messages. This error could be
used by an attacker to corrupt heap memory and crash the browser,
potentially running arbitrary code on a victim's computer.

MFSA 2010-03 / CVE-2009-1571: Security researcher Alin Rad Pop of
Secunia Research reported that the HTML parser incorrectly freed used
memory when insufficient space was available to process remaining
input. Under such circumstances, memory occupied by in-use objects was
freed and could later be filled with attacker-controlled text. These
conditions could result in the execution or arbitrary code if methods
on the freed objects were subsequently called.

MFSA 2010-04 / CVE-2009-3988: Security researcher Hidetake Jo of
Microsoft Vulnerability Research reported that the properties set on
an object passed to showModalDialog were readable by the document
contained in the dialog, even when the document was from a different
domain. This is a violation of the same-origin policy and could result
in a website running untrusted JavaScript if it assumed the
dialogArguments could not be initialized by another site.

An anonymous security researcher, via TippingPoint's Zero Day
Initiative, also independently reported this issue to Mozilla.

MFSA 2010-05 / CVE-2010-0162: Mozilla security researcher Georgi
Guninski reported that when a SVG document which is served with
Content-Type: application/octet-stream is embedded into another
document via an <embed> tag with type='image/svg+xml', the
Content-Type is ignored and the SVG document is processed normally. A
website which allows arbitrary binary data to be uploaded but which
relies on Content-Type: application/octet-stream to prevent script
execution could have such protection bypassed. An attacker could
upload a SVG document containing JavaScript as a binary file to a
website, embed the SVG document into a malicous page on another site,
and gain access to the script environment from the SVG-serving site,
bypassing the same-origin policy."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=576969"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 94, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-branding-upstream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:MozillaFirefox-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-xulrunner191-translations-other");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-xpcom191");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-3.5.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-branding-upstream-3.5.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-common-3.5.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"MozillaFirefox-translations-other-3.5.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-1.9.1.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-devel-1.9.1.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-kde4-0.6-0.1.2") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-common-1.9.1.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"mozilla-xulrunner191-translations-other-1.9.1.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"python-xpcom191-1.9.1.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.8-0.1.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.8-0.1.1") ) flag++;

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
