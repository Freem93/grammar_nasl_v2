#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update MozillaFirefox-5750.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(75951);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0450");

  script_name(english:"openSUSE Security Update : MozillaFirefox (MozillaFirefox-5750)");
  script_summary(english:"Check for the MozillaFirefox-5750 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 10 to fix bugs and security
issues.

MFSA 2012-01: Mozilla developers identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

In general these flaws cannot be exploited through email in the
Thunderbird and SeaMonkey products because scripting is disabled, but
are potentially a risk in browser or browser-like contexts in those
products. References

CVE-2012-0443: Ben Hawkes, Christian Holler, Honza Bombas, Jason
Orendorff, Jesse Ruderman, Jan Odvarko, Peter Van Der Beken, and Bill
McCloskey reported memory safety problems that were fixed in Firefox
10.

CVE-2012-0442: Jesse Ruderman and Bob Clary reported memory safety
problems that were fixed in both Firefox 10 and Firefox 3.6.26.

MFSA 2012-02/CVE-2011-3670: For historical reasons Firefox has been
generous in its interpretation of web addresses containing square
brackets around the host. If this host was not a valid IPv6 literal
address, Firefox attempted to interpret the host as a regular domain
name. Gregory Fleischer reported that requests made using IPv6 syntax
using XMLHttpRequest objects through a proxy may generate errors
depending on proxy configuration for IPv6. The resulting error
messages from the proxy may disclose sensitive data because
Same-Origin Policy (SOP) will allow the XMLHttpRequest object to read
these error messages, allowing user privacy to be eroded. Firefox now
enforces RFC 3986 IPv6 literal syntax and that may break links written
using the non-standard Firefox-only forms that were previously
accepted.

This was fixed previously for Firefox 7.0, Thunderbird 7.0, and
SeaMonkey 2.4 but only fixed in Firefox 3.6.26 and Thunderbird 3.1.18
during 2012.

MFSA 2012-03/CVE-2012-0445: Alex Dvorov reported that an attacker
could replace a sub-frame in another domain's document by using the
name attribute of the sub-frame as a form submission target. This can
potentially allow for phishing attacks against users and violates the
HTML5 frame navigation policy.

Firefox 3.6 and Thunderbird 3.1 are not affected by this vulnerability

MFSA 2012-04/CVE-2011-3659: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative that removed child nodes of
nsDOMAttribute can be accessed under certain circumstances because of
a premature notification of AttributeChildRemoved. This use-after-free
of the child nodes could possibly allow for for remote code execution.

MFSA 2012-05/CVE-2012-0446: Mozilla security researcher moz_bug_r_a4
reported that frame scripts bypass XPConnect security checks when
calling untrusted objects. This allows for cross-site scripting (XSS)
attacks through web pages and Firefox extensions. The fix enables the
Script Security Manager (SSM) to force security checks on all frame
scripts.

Firefox 3.6 and Thunderbird 3.1 are not affected by this vulnerability

MFSA 2012-06/CVE-2012-0447: Mozilla developer Tim Abraldes reported
that when encoding images as image/vnd.microsoft.icon the resulting
data was always a fixed size, with uninitialized memory appended as
padding beyond the size of the actual image. This is the result of
mImageBufferSize in the encoder being initialized with a value
different than the size of the source image. There is the possibility
of sensitive data from uninitialized memory being appended to a PNG
image when converted fron an ICO format image. This sensitive data may
then be disclosed in the resulting image.

Firefox 3.6 and Thunderbird 3.1 are not affected by this vulnerability

MFSA 2012-07/CVE-2012-0444: Security researcher regenrecht reported
via TippingPoint's Zero Day Initiative the possibility of memory
corruption during the decoding of Ogg Vorbis files. This can cause a
crash during decoding and has the potential for remote code execution.

MFSA 2012-08/CVE-2012-0449: Security researchers Nicolas Gregoire and
Aki Helin independently reported that when processing a malformed
embedded XSLT stylesheet, Firefox can crash due to a memory
corruption. While there is no evidence that this is directly
exploitable, there is a possibility of remote code execution.

MFSA 2012-09/CVE-2012-0450: magicant starmen reported that if a user
chooses to export their Firefox Sync key the 'Firefox Recovery
Key.html' file is saved with incorrect permissions, making the file
contents potentially readable by other users on Linux and OS X
systems.

Firefox 3.6 is not affected by this vulnerability."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=744275"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

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

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-10.0-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-branding-upstream-10.0-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-buildsymbols-10.0-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debuginfo-10.0-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-debugsource-10.0-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-devel-10.0-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-common-10.0-0.2.1") ) flag++;
if ( rpm_check(release:"SUSE11.4", reference:"MozillaFirefox-translations-other-10.0-0.2.1") ) flag++;

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
