#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2012:1351-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83562);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2012-3977", "CVE-2012-3982", "CVE-2012-3983", "CVE-2012-3984", "CVE-2012-3985", "CVE-2012-3986", "CVE-2012-3987", "CVE-2012-3988", "CVE-2012-3989", "CVE-2012-3990", "CVE-2012-3991", "CVE-2012-3992", "CVE-2012-3993", "CVE-2012-3994", "CVE-2012-3995", "CVE-2012-4179", "CVE-2012-4180", "CVE-2012-4181", "CVE-2012-4182", "CVE-2012-4183", "CVE-2012-4184", "CVE-2012-4185", "CVE-2012-4186", "CVE-2012-4187", "CVE-2012-4188", "CVE-2012-4192", "CVE-2012-4193");
  script_bugtraq_id(55856, 55857, 55889, 55922, 55924, 55926, 55927, 55929, 55930, 55931, 55932, 56118, 56119, 56120, 56121, 56123, 56125, 56126, 56127, 56128, 56129, 56130, 56131, 56135, 56136, 56140, 56145, 56154, 56155);

  script_name(english:"SUSE SLED10 / SLED11 / SLES10 / SLES11 Security Update : Mozilla Firefox (SUSE-SU-2012:1351-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 10.0.9ESR security release which
fixes bugs and security issues :

MFSA 2012-73 / CVE-2012-3977: Security researchers Thai Duong and
Juliano Rizzo reported that SPDY's request header compression leads to
information leakage, which can allow the extraction of private data
such as session cookies, even over an encrypted SSL connection. (This
does not affect Firefox 10 as it does not feature the SPDY extension.
It was silently fixed for Firefox 15.)

MFSA 2012-74: Mozilla developers identified and fixed
several memory safety bugs in the browser engine used in
Firefox and other Mozilla-based products. Some of these bugs
showed evidence of memory corruption under certain
circumstances, and we presume that with enough effort at
least some of these could be exploited to run arbitrary
code.

In general these flaws cannot be exploited through email in
the Thunderbird and SeaMonkey products because scripting is
disabled, but are potentially a risk in browser or
browser-like contexts in those products.

CVE-2012-3983: Henrik Skupin, Jesse Ruderman and
moz_bug_r_a4 reported memory safety problems and crashes
that affect Firefox 15.

CVE-2012-3982: Christian Holler and Jesse Ruderman reported
memory safety problems and crashes that affect Firefox ESR
10 and Firefox 15.

MFSA 2012-75 / CVE-2012-3984: Security researcher David
Bloom of Cue discovered that 'select' elements are
always-on-top chromeless windows and that navigation away
from a page with an active 'select' menu does not remove
this window.When another menu is opened programmatically on
a new page, the original 'select' menu can be retained and
arbitrary HTML content within it rendered, allowing an
attacker to cover arbitrary portions of the new page through
absolute positioning/scrolling, leading to spoofing attacks.
Security researcher Jordi Chancel found a variation that
would allow for click-jacking attacks was well.

In general these flaws cannot be exploited through email in
the Thunderbird and SeaMonkey products because scripting is
disabled, but are potentially a risk in browser or
browser-like contexts in those products. References

Navigation away from a page with an active 'select' dropdown
menu can be used for URL spoofing, other evil

Firefox 10.0.1 : Navigation away from a page with multiple
active 'select' dropdown menu can be used for Spoofing And
ClickJacking with XPI using window.open and geolocalisation

MFSA 2012-76 / CVE-2012-3985: Security researcher Collin
Jackson reported a violation of the HTML5 specifications for
document.domain behavior. Specified behavior requires pages
to only have access to windows in a new document.domain but
the observed violation allowed pages to retain access to
windows from the page's initial origin in addition to the
new document.domain. This could potentially lead to
cross-site scripting (XSS) attacks.

MFSA 2012-77 / CVE-2012-3986: Mozilla developer Johnny
Stenback discovered that several methods of a feature used
for testing (DOMWindowUtils) are not protected by existing
security checks, allowing these methods to be called through
script by web pages. This was addressed by adding the
existing security checks to these methods.

MFSA 2012-78 / CVE-2012-3987: Security researcher Warren He
reported that when a page is transitioned into Reader Mode
in Firefox for Android, the resulting page has chrome
privileges and its content is not thoroughly sanitized. A
successful attack requires user enabling of reader mode for
a malicious page, which could then perform an attack similar
to cross-site scripting (XSS) to gain the privileges allowed
to Firefox on an Android device. This has been fixed by
changing the Reader Mode page into an unprivileged page.

This vulnerability only affects Firefox for Android.

MFSA 2012-79 / CVE-2012-3988: Security researcher Soroush
Dalili reported that a combination of invoking full screen
mode and navigating backwards in history could, in some
circumstances, cause a hang or crash due to a timing
dependent use-after-free pointer reference. This crash may
be potentially exploitable.

MFSA 2012-80 / CVE-2012-3989: Mozilla community member
Ms2ger reported a crash due to an invalid cast when using
the instanceof operator on certain types of JavaScript
objects. This can lead to a potentially exploitable crash.

MFSA 2012-81 / CVE-2012-3991: Mozilla community member Alice
White reported that when the GetProperty function is invoked
through JSAPI, security checking can be bypassed when
getting cross-origin properties. This potentially allowed
for arbitrary code execution.

MFSA 2012-82 / CVE-2012-3994: Security researcher Mariusz
Mlynski reported that the location property can be accessed
by binary plugins through top.location and top can be
shadowed by Object.defineProperty as well. This can allow
for possible cross-site scripting (XSS) attacks through
plugins.

MFSA 2012-83: Security researcher Mariusz Mlynski reported
that when InstallTrigger fails, it throws an error wrapped
in a Chrome Object Wrapper (COW) that fails to specify
exposed properties. These can then be added to the resulting
object by an attacker, allowing access to chrome privileged
functions through script.

While investigating this issue, Mozilla security researcher
moz_bug_r_a4 found that COW did not disallow accessing of
properties from a standard prototype in some situations,
even when the original issue had been fixed.

These issues could allow for a cross-site scripting (XSS)
attack or arbitrary code execution.

CVE-2012-3993: XrayWrapper pollution via unsafe COW

CVE-2012-4184: ChromeObjectWrapper is not implemented as
intended

MFSA 2012-84 / CVE-2012-3992: Security researcher Mariusz
Mlynski reported an issue with spoofing of the location
property. In this issue, writes to location.hash can be used
in concert with scripted history navigation to cause a
specific website to be loaded into the history object. The
baseURI can then be changed to this stored site, allowing an
attacker to inject a script or intercept posted data posted
to a location specified with a relative path.

MFSA 2012-85: Security researcher Abhishek Arya (Inferno) of
the Google Chrome Security Team discovered a series of
use-after-free, buffer overflow, and out of bounds read
issues using the Address Sanitizer tool in shipped software.
These issues are potentially exploitable, allowing for
remote code execution. We would also like to thank Abhishek
for reporting two additional use-after-free flaws introduced
during Firefox 16 development and fixed before general
release.

CVE-2012-3995: Out of bounds read in IsCSSWordSpacingSpace

CVE-2012-4179: Heap-use-after-free in
nsHTMLCSSUtils::CreateCSSPropertyTxn

CVE-2012-4180: Heap-buffer-overflow in
nsHTMLEditor::IsPrevCharInNodeWhitespace

CVE-2012-4181: Heap-use-after-free in
nsSMILAnimationController::DoSample

CVE-2012-4182: Heap-use-after-free in
nsTextEditRules::WillInsert

CVE-2012-4183: Heap-use-after-free in
DOMSVGTests::GetRequiredFeatures

MFSA 2012-86: Security researcher Atte Kettunen from OUSPG
reported several heap memory corruption issues found using
the Address Sanitizer tool. These issues are potentially
exploitable, allowing for remote code execution.

CVE-2012-4185: Global-buffer-overflow in
nsCharTraits::length

CVE-2012-4186: Heap-buffer-overflow in
nsWaveReader::DecodeAudioData

CVE-2012-4187: Crash with ASSERTION: insPos too small

CVE-2012-4188: Heap-buffer-overflow in Convolve3x3

MFSA 2012-87 / CVE-2012-3990: Security researcher miaubiz
used the Address Sanitizer tool to discover a use-after-free
in the IME State Manager code. This could lead to a
potentially exploitable crash.

MFSA 2012-89 / CVE-2012-4192 / CVE-2012-4193: Mozilla
security researcher moz_bug_r_a4 reported a regression where
security wrappers are unwrapped without doing a security
check in defaultValue(). This can allow for improper access
access to the Location object. In versions 15 and earlier of
affected products, there was also the potential for
arbitrary code execution.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=9df8424f201589e4fca1abdc2e0b1023
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dae39bfb"
  );
  # http://download.suse.com/patch/finder/?keywords=b54051bb7b93d9b879c04f373ce0061d
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c39018cb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3977.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3982.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3984.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3985.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3986.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3987.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3988.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3989.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3990.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3991.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3992.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3993.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3994.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4184.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4186.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4187.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4188.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-4193.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/783533"
  );
  # https://www.suse.com/support/update/announcement/2012/suse-su-20121351-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1da16d4d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 for VMware :

zypper in -t patch slessp2-firefox-201210-6951

SUSE Linux Enterprise Server 11 SP2 :

zypper in -t patch slessp2-firefox-201210-6951

SUSE Linux Enterprise Desktop 11 SP2 :

zypper in -t patch sledsp2-firefox-201210-6951

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 5.0 - 15.0.1 __exposedProps__ XCS Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED10|SLED11|SLES10|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED10 / SLED11 / SLES10 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);
if (os_ver == "SLED10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLED10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);
if (os_ver == "SLED11" && (! ereg(pattern:"^2$", string:sp))) audit(AUDIT_OS_NOT, "SLED11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-10.0.9-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-branding-SLED-7-0.6.7.85")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"MozillaFirefox-translations-10.0.9-0.3.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-10.0.9-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.8.35")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.9-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"MozillaFirefox-10.0.9-0.5.1")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.8.35")) flag++;
if (rpm_check(release:"SLED10", sp:"4", cpu:"i586", reference:"MozillaFirefox-translations-10.0.9-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-10.0.9-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-branding-SLED-7-0.8.35")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-translations-10.0.9-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-10.0.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.6.7.85")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"MozillaFirefox-10.0.9-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.6.7.85")) flag++;
if (rpm_check(release:"SLED11", sp:"2", cpu:"i586", reference:"MozillaFirefox-translations-10.0.9-0.3.1")) flag++;


if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla Firefox");
}
