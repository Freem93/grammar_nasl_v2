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
  script_id(58524);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2012-0451", "CVE-2012-0454", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0463", "CVE-2012-0464");

  script_name(english:"SuSE 11.1 Security Update : Mozilla Firefox (SAT Patch Number 6007)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 10.0.3 ESR to fix various bugs and
security issues.

The following security issues have been fixed :

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-19)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.

    References :

    Bob Clary reported two bugs that causes crashes that
    affected Firefox 3.6, Firefox ESR, and Firefox 10.
    (CVE-2012-0461)

    Christian Holler, Jesse Ruderman, Nils, Michael
    Bebenita, Dindog, and David Anderson reported memory
    safety problems and crashes that affect Firefox ESR and
    Firefox 10. (CVE-2012-0462)

    Jeff Walden reported a memory safety problem in the
    array.join function. This bug was independently reported
    by Vincenzo Iozzo via TippingPoint's Zero Day Initiative
    Pwn2Own contest. (CVE-2012-0464)

    Masayuki Nakano reported a memory safety problem that
    affected Mobile Firefox

  - CVE-2012-0463

  - Mozilla developer Matt Brubeck reported that
    window.fullScreen is writeable by untrusted content now
    that the DOM fullscreen API is enabled. Because
    window.fullScreen does not include
    mozRequestFullscreen's security protections, it could be
    used for UI spoofing. This code change makes
    window.fullScreen read only by untrusted content,
    forcing the use of the DOM fullscreen API in normal
    usage. (MFSA 2012-18 / CVE-2012-0460)

    Firefox 3.6 and Thunderbird 3.1 are not affected by this
    vulnerability.

  - Mozilla community member Daniel Glazman of Disruptive
    Innovations reported a crash when accessing a keyframe's
    cssText after dynamic modification. This crash may be
    potentially exploitable. (MFSA 2012-17 / CVE-2012-0459)

    Firefox 3.6 and Thunderbird 3.1 are not affected by this
    vulnerability.

  - Security researcher Mariusz Mlynski reported that an
    attacker able to convince a potential victim to set a
    new home page by dragging a link to the 'home' button
    can set that user's home page to a javascript: URL. Once
    this is done the attacker's page can cause repeated
    crashes of the browser, eventually getting the script
    URL loaded in the privileged about:sessionrestore
    context. (MFSA 2012-16 / CVE-2012-0458)

  - Security Researcher Mike Brooks of Sitewatch reported
    that if multiple Content Security Policy (CSP) headers
    are present on a page, they have an additive effect page
    policy. Using carriage return line feed (CRLF)
    injection, a new CSP rule can be introduced which allows
    for cross-site scripting (XSS) on sites with a separate
    header injection vulnerability. (MFSA 2012-15 /
    CVE-2012-0451)

    Firefox 3.6 and Thunderbird 3.1 are not affected by this
    vulnerability.

  - Security researcher Atte Kettunen from OUSPG found two
    issues with Firefox's handling of SVG using the Address
    Sanitizer tool. The first issue, critically rated, is a
    use-after-free in SVG animation that could potentially
    lead to arbitrary code execution. The second issue is
    rated moderate and is an out of bounds read in SVG
    Filters. This could potentially incorporate data from
    the user's memory, making it accessible to the page
    content. (MFSA 2012-14 / CVE-2012-0457 / CVE-2012-0456)

  - Firefox prevents the dropping of javascript: links onto
    a frame to prevent malicious sites from tricking users
    into performing a cross-site scripting (XSS) attacks on
    themselves. Security researcher Soroush Dalili reported
    a way to bypass this protection. (MFSA 2012-13 /
    CVE-2012-0455)

  - Security researchers Blair Strang and Scott Bell of
    Security Assessment found that when a parent window
    spawns and closes a child window that uses the file open
    dialog, a crash can be induced in shlwapi.dll on 32-bit
    Windows 7 systems. This crash may be potentially
    exploitable. (MFSA 2012-12 / CVE-2012-0454)

    Firefox 3.6 and Thunderbird 3.1 are not affected by this
    vulnerability.

  - Reworked the KDE4 integration. (bnc#745017)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=745017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=750044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0451.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0454.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0455.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0456.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0457.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0458.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0460.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0461.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0462.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0464.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-10.0.3-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-translations-10.0.3-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libfreebl3-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nspr-4.9.0-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nss-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-nss-tools-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-10.0.3-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.3-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libfreebl3-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libfreebl3-32bit-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-4.9.0-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.0-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-nss-tools-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-10.0.3-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-translations-10.0.3-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libfreebl3-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nspr-4.9.0-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nss-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-nss-tools-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libfreebl3-32bit-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.0-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-nss-32bit-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libfreebl3-32bit-3.13.3-0.2.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.0-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.3-0.2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
