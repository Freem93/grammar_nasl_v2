#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73147);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/01/06 15:36:34 $");

  script_cve_id("CVE-2014-1493", "CVE-2014-1494", "CVE-2014-1496", "CVE-2014-1497", "CVE-2014-1498", "CVE-2014-1499", "CVE-2014-1500", "CVE-2014-1501", "CVE-2014-1502", "CVE-2014-1504", "CVE-2014-1505", "CVE-2014-1508", "CVE-2014-1509", "CVE-2014-1510", "CVE-2014-1511", "CVE-2014-1512", "CVE-2014-1513", "CVE-2014-1514");

  script_name(english:"SuSE 11.3 Security Update : MozillaFirefox (SAT Patch Number 9049)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 24.4.0ESR release, fixing various
security issues and bugs :

  - Mozilla developers and community identified identified
    and fixed several memory safety bugs in the browser
    engine used in Firefox and other Mozilla-based products.
    Some of these bugs showed evidence of memory corruption
    under certain circumstances, and we presume that with
    enough effort at least some of these could be exploited
    to run arbitrary code. (MFSA 2014-15)

  - Benoit Jacob, Olli Pettay, Jan Varga, Jan de Mooij,
    Jesse Ruderman, Dan Gohman, and Christoph Diehl reported
    memory safety problems and crashes that affect Firefox
    ESR 24.3 and Firefox 27. (CVE-2014-1493)

  - Gregor Wagner, Olli Pettay, Gary Kwong, Jesse Ruderman,
    Luke Wagner, Rob Fletcher, and Makoto Kato reported
    memory safety problems and crashes that affect Firefox
    27. (CVE-2014-1494)

  - Security researcher Ash reported an issue where the
    extracted files for updates to existing files are not
    read only during the update process. This allows for the
    potential replacement or modification of these files
    during the update process if a malicious application is
    present on the local system. (MFSA 2014-16 /
    CVE-2014-1496)

  - Security researcher Atte Kettunen from OUSPG reported an
    out of bounds read during the decoding of WAV format
    audio files for playback. This could allow web content
    access to heap data as well as causing a crash. (MFSA
    2014-17 / CVE-2014-1497)

  - Mozilla developer David Keeler reported that the
    crypto.generateCRFMRequest method did not correctly
    validate the key type of the KeyParams argument when
    generating ec-dual-use requests. This could lead to a
    crash and a denial of service (DOS) attack. (MFSA
    2014-18 / CVE-2014-1498)

  - Mozilla developer Ehsan Akhgari reported a spoofing
    attack where the permission prompt for a WebRTC session
    can appear to be from a different site than its actual
    originating site if a timed navigation occurs during the
    prompt generation. This allows an attacker to
    potentially gain access to the webcam or microphone by
    masquerading as another site and gaining user permission
    through spoofing. (MFSA 2014-19 / CVE-2014-1499)

  - Security researchers Tim Philipp Schaefers and Sebastian
    Neef, the team of Internetwache.org, reported a
    mechanism using JavaScript onbeforeunload events with
    page navigation to prevent users from closing a
    malicious page's tab and causing the browser to become
    unresponsive. This allows for a denial of service (DOS)
    attack due to resource consumption and blocks the
    ability of users to exit the application. (MFSA 2014-20
    / CVE-2014-1500)

  - Security researcher Alex Infuehr reported that on
    Firefox for Android it is possible to open links to
    local files from web content by selecting 'Open Link in
    New Tab' from the context menu using the file: protocol.
    The web content would have to know the precise location
    of a malicious local file in order to exploit this
    issue. This issue does not affect Firefox on non-Android
    systems. (MFSA 2014-21 / CVE-2014-1501)

  - Mozilla developer Jeff Gilbert discovered a mechanism
    where a malicious site with WebGL content could inject
    content from its context to that of another site's WebGL
    context, causing the second site to replace textures and
    similar content. This cannot be used to steal data but
    could be used to render arbitrary content in these
    limited circumstances. (MFSA 2014-22 / CVE-2014-1502)

  - Security researcher Nicolas Golubovic reported that the
    Content Security Policy (CSP) of data: documents was not
    saved as part of session restore. If an attacker
    convinced a victim to open a document from a data: URL
    injected onto a page, this can lead to a Cross-Site
    Scripting (XSS) attack. The target page may have a
    strict CSP that protects against this XSS attack, but if
    the attacker induces a browser crash with another bug,
    an XSS attack would occur during session restoration,
    bypassing the CSP on the site. (MFSA 2014-23 /
    CVE-2014-1504)

  - Security researcher Tyson Smith and Jesse
    Schwartzentruber of the BlackBerry Security Automated
    Analysis Team used the Address Sanitizer tool while
    fuzzing to discover an out-of-bounds read during polygon
    rendering in MathML. This can allow web content to
    potentially read protected memory addresses. In
    combination with previous techniques used for SVG timing
    attacks, this could allow for text values to be read
    across domains, leading to information disclosure. (MFSA
    2014-26 / CVE-2014-1508)

  - Security researcher John Thomson discovered a memory
    corruption in the Cairo graphics library during font
    rendering of a PDF file for display. This memory
    corruption leads to a potentially exploitable crash and
    to a denial of service (DOS). This issues is not able to
    be triggered in a default configuration and would
    require a malicious extension to be installed. (MFSA
    2014-27 / CVE-2014-1509)

  - Mozilla developer Robert O'Callahan reported a mechanism
    for timing attacks involving SVG filters and
    displacements input to feDisplacementMap. This allows
    displacements to potentially be correlated with values
    derived from content. This is similar to the previously
    reported techniques used for SVG timing attacks and
    could allow for text values to be read across domains,
    leading to information disclosure. (MFSA 2014-28 /
    CVE-2014-1505)

  - Security researcher Mariusz Mlynski, via TippingPoint's
    Pwn2Own contest, reported that it is possible for
    untrusted web content to load a chrome-privileged page
    by getting JavaScript-implemented WebIDL to call
    window.open(). A second bug allowed the bypassing of the
    popup-blocker without user interaction. Combined these
    two bugs allow an attacker to load a JavaScript URL that
    is executed with the full privileges of the browser,
    which allows arbitrary code execution. (MFSA 2014-29 /
    CVE-2014-1510 / CVE-2014-1511)

  - Security research firm VUPEN, via TippingPoint's Pwn2Own
    contest, reported that memory pressure during Garbage
    Collection could lead to memory corruption of
    TypeObjects in the JS engine, resulting in an
    exploitable use-after-free condition. (MFSA 2014-30 /
    CVE-2014-1512)

  - Security researcher Jueri Aedla, via TippingPoint's
    Pwn2Own contest, reported that TypedArrayObject does not
    handle the case where ArrayBuffer objects are neutered,
    setting their length to zero while still in use. This
    leads to out-of-bounds reads and writes into the
    JavaScript heap, allowing for arbitrary code execution.
    (MFSA 2014-31 / CVE-2014-1513)

  - Security researcher George Hotz, via TippingPoint's
    Pwn2Own contest, discovered an issue where values are
    copied from an array into a second, neutered array. This
    allows for an out-of-bounds write into memory, causing
    an exploitable crash leading to arbitrary code
    execution. (MFSA 2014-32 / CVE-2014-1514)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-31.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2014/mfsa2014-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=868603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1496.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1498.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1499.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1500.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1501.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1502.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1504.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1505.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1508.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1509.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1511.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1512.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1513.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1514.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9049.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox WebIDL Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-24.4.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-branding-SLED-24-0.7.23")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"MozillaFirefox-translations-24.4.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"mozilla-nspr-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-24.4.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-24-0.7.23")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"MozillaFirefox-translations-24.4.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-24.4.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-branding-SLED-24-0.7.23")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"MozillaFirefox-translations-24.4.0esr-0.8.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"mozilla-nspr-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.4-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
