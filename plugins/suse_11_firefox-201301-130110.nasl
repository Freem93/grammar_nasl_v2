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
  script_id(64136);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/22 11:17:46 $");

  script_cve_id("CVE-2012-5829", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0751", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0761", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0766", "CVE-2013-0767", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771");

  script_name(english:"SuSE 11.2 Security Update : MozillaFirefox (SAT Patch Number 7224)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to the 10.0.12ESR release.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2013-01)

  - Christoph Diehl, Christian Holler, Mats Palmgren, and
    Chiaki Ishikawa reported memory safety problems and
    crashes that affect Firefox ESR 10, Firefox ESR 17, and
    Firefox 17. (CVE-2013-0769)

  - Bill Gianopoulos, Benoit Jacob, Christoph Diehl,
    Christian Holler, Gary Kwong, Robert O'Callahan, and
    Scoobidiver reported memory safety problems and crashes
    that affect Firefox ESR 17 and Firefox 17.
    (CVE-2013-0749)

  - Jesse Ruderman, Christian Holler, Julian Seward, and
    Scoobidiver reported memory safety problems and crashes
    that affect Firefox 17. (CVE-2013-0770)

  - Security researcher Abhishek Arya (Inferno) of the
    Google Chrome Security Team discovered a series
    critically rated of use-after-free, out of bounds read,
    and buffer overflow issues using the Address Sanitizer
    tool in shipped software. These issues are potentially
    exploitable, allowing for remote code execution. We
    would also like to thank Abhishek for reporting three
    additional user-after-free and out of bounds read flaws
    introduced during Firefox development that were fixed
    before general release. (MFSA 2013-02)

The following issue was fixed in Firefox 18 :

  - Global-buffer-overflow in
    CharDistributionAnalysis::HandleOneChar. (CVE-2013-0760)

The following issues were fixed in Firefox 18, ESR 17.0.1, and ESR
10.0.12 :

  - Heap-use-after-free in imgRequest::OnStopFrame.
    (CVE-2013-0762)

  - Heap-use-after-free in ~nsHTMLEditRules. (CVE-2013-0766)

  - Out of bounds read in
    nsSVGPathElement::GetPathLengthScale. (CVE-2013-0767)

The following issues were fixed in Firefox 18 and ESR 17.0.1 :

  - Heap-use-after-free in
    mozilla::TrackUnionStream::EndTrack. (CVE-2013-0761)

  - Heap-use-after-free in Mesa, triggerable by resizing a
    WebGL canvas. (CVE-2013-0763)

  - Heap-buffer-overflow in
    gfxTextRun::ShrinkToLigatureBoundaries. (CVE-2013-0771)

The following issue was fixed in Firefox 18 and in the earlier ESR
10.0.11 release :

  - Heap-buffer-overflow in nsWindow::OnExposeEvent.
    (CVE-2012-5829)

  - Security researcher miaubiz used the Address Sanitizer
    tool to discover a buffer overflow in Canvas when
    specific bad height and width values were given through
    HTML. This could lead to a potentially exploitable
    crash. (CVE-2013-0768). (MFSA 2013-03)

    Miaubiz also found a potentially exploitable crash when
    2D and 3D content was mixed which was introduced during
    Firefox development and fixed before general release.

  - Security researcher Masato Kinugawa found a flaw in
    which the displayed URL values within the addressbar can
    be spoofed by a page during loading. This allows for
    phishing attacks where a malicious page can spoof the
    identify of another site. (CVE-2013-0759). (MFSA
    2013-04)

  - Using the Address Sanitizer tool, security researcher
    Atte Kettunen from OUSPG discovered that the combination
    of large numbers of columns and column groups in a table
    could cause the array containing the columns during
    rendering to overwrite itself. This can lead to a
    user-after-free causing a potentially exploitable crash.
    (CVE-2013-0744). (MFSA 2013-05)

  - Mozilla developer Wesley Johnston reported that when
    there are two or more iframes on the same HTML page, an
    iframe is able to see the touch events and their targets
    that occur within the other iframes on the page. If the
    iframes are from the same origin, they can also access
    the properties and methods of the targets of other
    iframes but same-origin policy (SOP) restricts access
    across domains. This allows for information leakage and
    possibilities for cross-site scripting (XSS) if another
    vulnerability can be used to get around SOP
    restrictions. (CVE-2013-0751). (MFSA 2013-06)

  - Mozilla community member Jerry Baker reported a crashing
    issue found through Thunderbird when downloading
    messages over a Secure Sockets Layer (SSL) connection.
    This was caused by a bug in the networking code assuming
    that secure connections were entirely handled on the
    socket transport thread when they can occur on a variety
    of threads. The resulting crash was potentially
    exploitable. (CVE-2013-0764). (MFSA 2013-07)

  - Mozilla developer Olli Pettay discovered that the
    AutoWrapperChanger class fails to keep some JavaScript
    objects alive during garbage collection. This can lead
    to an exploitable crash allowing for arbitrary code
    execution. (CVE-2013-0745). (MFSA 2013-08)

  - Mozilla developer Boris Zbarsky reported reported a
    problem where jsval-returning quickstubs fail to wrap
    their return values, causing a compartment mismatch.
    This mismatch can cause garbage collection to occur
    incorrectly and lead to a potentially exploitable crash.
    (CVE-2013-0746). (MFSA 2013-09)

  - Mozilla security researcher Jesse Ruderman reported that
    events in the plugin handler can be manipulated by web
    content to bypass same-origin policy (SOP) restrictions.
    This can allow for clickjacking on malicious web pages.
    (CVE-2013-0747). (MFSA 2013-10)

  - Mozilla security researcher Jesse Ruderman discovered
    that using the toString function of XBL objects can lead
    to inappropriate information leakage by revealing the
    address space layout instead of just the ID of the
    object. This layout information could potentially be
    used to bypass ASLR and other security protections.
    (CVE-2013-0748). (MFSA 2013-11)

  - Security researcher pa_kt reported a flaw via
    TippingPoint's Zero Day Initiative that an integer
    overflow is possible when calculating the length for a
    JavaScript string concatenation, which is then used for
    memory allocation. This results in a buffer overflow,
    leading to a potentially exploitable memory corruption.
    (CVE-2013-0750). (MFSA 2013-12)

  - Security researcher Sviatoslav Chagaev reported that
    when using an XBL file containing multiple XML bindings
    with SVG content, a memory corruption can occur. In
    concern with remote XUL, this can lead to an exploitable
    crash. (CVE-2013-0752). (MFSA 2013-13)

  - Security researcher Mariusz Mlynski reported that it is
    possible to change the prototype of an object and bypass
    Chrome Object Wrappers (COW) to gain access to chrome
    privileged functions. This could allow for arbitrary
    code execution. (CVE-2013-0757). (MFSA 2013-14)

  - Security researcher Mariusz Mlynski reported that it is
    possible to open a chrome privileged web page through
    plugin objects through interaction with SVG elements.
    This could allow for arbitrary code execution.
    (CVE-2013-0758). (MFSA 2013-15)

  - Security researcher regenrecht reported, via
    TippingPoint's Zero Day Initiative, a use-after-free in
    XMLSerializer by the exposing of serializeToStream to
    web content. This can lead to arbitrary code execution
    when exploited. (CVE-2013-0753). (MFSA 2013-16)

  - Security researcher regenrecht reported, via
    TippingPoint's Zero Day Initiative, a use-after-free
    within the ListenerManager when garbage collection is
    forced after data in listener objects have been
    allocated in some circumstances. This results in a
    use-after-free which can lead to arbitrary code
    execution. (CVE-2013-0754). (MFSA 2013-17)

  - Security researcher regenrecht reported, via
    TippingPoint's Zero Day Initiative, a use-after-free
    using the domDoc pointer within Vibrate library. This
    can lead to arbitrary code execution when exploited.
    (CVE-2013-0755). (MFSA 2013-18)

  - Security researcher regenrecht reported, via
    TippingPoint's Zero Day Initiative, a garbage collection
    flaw in JavaScript Proxy objects. This can lead to a
    use-after-free leading to arbitrary code execution.
    (CVE-2013-0756). (MFSA 2013-19)

  - Google reported to Mozilla that TURKTRUST, a certificate
    authority in Mozilla's root program, had mis-issued two
    intermediate certificates to customers. The issue was
    not specific to Firefox but there was evidence that one
    of the certificates was used for man-in-the-middle
    (MITM) traffic management of domain names that the
    customer did not legitimately own or control. This issue
    was resolved by revoking the trust for these specific
    mis-issued certificates. (CVE-2013-0743). (MFSA 2013-20)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-02.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-06.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-10.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-11.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-13.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-14.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-15.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2013/mfsa2013-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=796895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-5829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0744.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0745.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0746.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0747.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0748.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0749.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0750.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0751.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0753.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0754.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0755.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0756.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0757.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0758.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0759.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0760.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0761.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0762.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0763.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0764.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0766.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0768.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0769.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0770.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0771.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7224.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 17.0.1 Flash Privileged Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-10.0.12-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-10.0.12-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libfreebl3-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nspr-4.9.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-tools-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-10.0.12-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.12-0.4.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-4.9.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.4-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-tools-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-10.0.12-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-translations-10.0.12-0.4.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libfreebl3-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nspr-4.9.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-tools-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libfreebl3-32bit-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nss-32bit-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.14.1-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.4-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.1-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
