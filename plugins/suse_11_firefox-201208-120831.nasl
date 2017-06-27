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
  script_id(64132);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:41:53 $");

  script_cve_id("CVE-2012-1956", "CVE-2012-1970", "CVE-2012-1971", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3965", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3971", "CVE-2012-3972", "CVE-2012-3973", "CVE-2012-3974", "CVE-2012-3975", "CVE-2012-3976", "CVE-2012-3978", "CVE-2012-3979", "CVE-2012-3980");

  script_name(english:"SuSE 11.2 Security Update : Mozilla Firefox (SAT Patch Number 6763)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to 10.0.7ESR release, fixing a lot of bugs
and security problems.

The following security issues have been addressed :

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-57)

    In general these flaws cannot be exploited through email
    in the Thunderbird and SeaMonkey products because
    scripting is disabled, but are potentially a risk in
    browser or browser-like contexts in those products.

  - Gary Kwong, Christian Holler, Jesse Ruderman, Steve
    Fink, Bob Clary, Andrew Sutherland, and Jason Smith
    reported memory safety problems and crashes that affect
    Firefox 14. (CVE-2012-1971)

  - Gary Kwong, Christian Holler, Jesse Ruderman, John
    Schoenick, Vladimir Vukicevic and Daniel Holbert
    reported memory safety problems and crashes that affect
    Firefox ESR 10 and Firefox 14. (CVE-2012-1970)

  - Security researcher Abhishek Arya (Inferno) of Google
    Chrome Security Team discovered a series of
    use-after-free issues using the Address Sanitizer tool.
    Many of these issues are potentially exploitable,
    allowing for remote code execution. (MFSA 2012-58)

  - Heap-use-after-free in
    nsHTMLEditor::CollapseAdjacentTextNodes. (CVE-2012-1972)

  - Heap-use-after-free in
    nsObjectLoadingContent::LoadObject. (CVE-2012-1973)

  - Heap-use-after-free in gfxTextRun::CanBreakLineBefore.
    (CVE-2012-1974)

  - Heap-use-after-free in PresShell::CompleteMove.
    (CVE-2012-1975)

  - Heap-use-after-free in
    nsHTMLSelectElement::SubmitNamesValues. (CVE-2012-1976)

  - Heap-use-after-free in
    MediaStreamGraphThreadRunnable::Run(). (CVE-2012-3956)

  - Heap-buffer-overflow in nsBlockFrame::MarkLineDirty.
    (CVE-2012-3957)

  - Heap-use-after-free in
    nsHTMLEditRules::DeleteNonTableElements. (CVE-2012-3958)

  - Heap-use-after-free in nsRangeUpdater::SelAdjDeleteNode.
    (CVE-2012-3959)

  - Heap-use-after-free in
    mozSpellChecker::SetCurrentDictionary. (CVE-2012-3960)

  - Heap-use-after-free in RangeData::~RangeData.
    (CVE-2012-3961)

  - Bad iterator in text runs. (CVE-2012-3962)

  - use after free in js::gc::MapAllocToTraceKind.
    (CVE-2012-3963)

  - Heap-use-after-free READ 8 in gfxTextRun::GetUserData.
    (CVE-2012-3964)

  - Security researcher Mariusz Mlynski reported that it is
    possible to shadow the location object using
    Object.defineProperty. This could be used to confuse the
    current location to plugins, allowing for possible
    cross-site scripting (XSS) attacks. (MFSA 2012-59 /
    CVE-2012-1956)

  - Security researcher Mariusz Mlynski reported that when a
    page opens a new tab, a subsequent window can then be
    opened that can be navigated to about:newtab, a chrome
    privileged page. Once about:newtab is loaded, the
    special context can potentially be used to escalate
    privilege, allowing for arbitrary code execution on the
    local system in a maliciously crafted attack. (MFSA
    2012-60 / CVE-2012-3965)

  - Security researcher Frederic Hoguin reported two related
    issues with the decoding of bitmap (.BMP) format images
    embedded in icon (.ICO) format files. When processing a
    negative 'height' header value for the bitmap image, a
    memory corruption can be induced, allowing an attacker
    to write random memory and cause a crash. This crash may
    be potentially exploitable. (MFSA 2012-61 /
    CVE-2012-3966)

  - Security researcher miaubiz used the Address Sanitizer
    tool to discover two WebGL issues. The first issue is a
    use-after-free when WebGL shaders are called after being
    destroyed. The second issue exposes a problem with Mesa
    drivers on Linux, leading to a potentially exploitable
    crash. (MFSA 2012-62)

  - use after free, webgl fragment shader deleted by
    accessor. (CVE-2012-3968)

  - stack scribbling with 4-byte values choosable among a
    few values, when using more than 16 sampler uniforms, on
    Mesa, with all drivers CVE-2012-3967

  - Security researcher Arthur Gerkis used the Address
    Sanitizer tool to find two issues involving Scalable
    Vector Graphics (SVG) files. The first issue is a buffer
    overflow in Gecko's SVG filter code when the sum of two
    values is too large to be stored as a signed 32-bit
    integer, causing the function to write past the end of
    an array. The second issue is a use-after-free when an
    element with a 'requiredFeatures' attribute is moved
    between documents. In that situation, the internal
    representation of the 'requiredFeatures' value could be
    freed prematurely. Both issues are potentially
    exploitable. (MFSA 2012-63)

  - Heap-buffer-overflow in
    nsSVGFEMorphologyElement::Filter. (CVE-2012-3969)

  - Heap-use-after-free in nsTArray_base::Length().
    (CVE-2012-3970)

  - Using the Address Sanitizer tool, Mozilla security
    researcher Christoph Diehl discovered two memory
    corruption issues involving the Graphite 2 library used
    in Mozilla products. Both of these issues can cause a
    potentially exploitable crash. These problems were fixed
    in the Graphite 2 library, which has been updated for
    Mozilla products. (MFSA 2012-64 / CVE-2012-3971)

  - Security research Nicolas Gregoire used the Address
    Sanitizer tool to discover an out-of-bounds read in the
    format-number feature of XSLT, which can cause
    inaccurate formatting of numbers and information
    leakage. This is not directly exploitable. (MFSA 2012-65
    / CVE-2012-3972)

  - Mozilla security researcher Mark Goodwin discovered an
    issue with the Firefox developer tools' debugger. If
    remote debugging is disabled, but the experimental
    HTTPMonitor extension has been installed and enabled, a
    remote user can connect to and use the remote debugging
    service through the port used by HTTPMonitor. A
    remote-enabled flag has been added to resolve this
    problem and close the port unless debugging is
    explicitly enabled. (MFSA 2012-66 / CVE-2012-3973)

  - Security researcher Masato Kinugawa reported that if a
    crafted executable is placed in the root partition on a
    Windows file system, the Firefox and Thunderbird
    installer will launch this program after a standard
    installation instead of Firefox or Thunderbird, running
    this program with the user's privileges. (MFSA 2012-67 /
    CVE-2012-3974)

  - Security researcher vsemozhetbyt reported that when the
    DOMParser is used to parse text/html data in a Firefox
    extension, linked resources within this HTML data will
    be loaded. If the data being parsed in the extension is
    untrusted, it could lead to information leakage and can
    potentially be combined with other attacks to become
    exploitable. (MFSA 2012-68 / CVE-2012-3975)

  - Security researcher Mark Poticha reported an issue where
    incorrect SSL certificate information can be displayed
    on the addressbar, showing the SSL data for a previous
    site while another has been loaded. This is caused by
    two onLocationChange events being fired out of the
    expected order, leading to the displayed certificate
    data to not be updated. This can be used for phishing
    attacks by allowing the user to input form or other data
    on a newer, attacking, site while the credentials of an
    older site appear on the addressbar. (MFSA 2012-69 /
    CVE-2012-3976)

  - Mozilla security researcher moz_bug_r_a4 reported that
    certain security checks in the location object can be
    bypassed if chrome code is called content in a specific
    manner. This allowed for the loading of restricted
    content. This can be combined with other issues to
    become potentially exploitable. (MFSA 2012-70 /
    CVE-2012-3978)

  - Mozilla developer Blake Kaplan reported that
    __android_log_print is called insecurely in places. If a
    malicious web page used a dump() statement with a
    specially crafted string, it can trigger a potentially
    exploitable crash. (MFSA 2012-71 / CVE-2012-3979)

    This vulnerability only affects Firefox for Android.

  - Security researcher Colby Russell discovered that eval
    in the web console can execute injected code with chrome
    privileges, leading to the running of malicious code in
    a privileged context. This allows for arbitrary code
    execution through a malicious web page if the web
    console is invoked by the user. (MFSA 2012-72 /
    CVE-2012-3980)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-57.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-58.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-59.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-60.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-61.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-62.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-63.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-64.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-65.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-66.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-67.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-68.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-69.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-70.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-71.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-72.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=777588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1971.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1972.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1973.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1975.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-1976.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3957.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3958.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3959.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3960.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3961.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3962.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3963.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3964.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3965.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3966.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3967.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3968.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3969.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3971.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3972.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3973.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3975.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3976.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3978.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3979.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-3980.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 6763.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-10.0.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.6.7.80")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"MozillaFirefox-translations-10.0.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"libfreebl3-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nspr-4.9.2-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"mozilla-nss-tools-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-10.0.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.6.7.80")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"MozillaFirefox-translations-10.0.7-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-4.9.2-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.2-0.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"mozilla-nss-tools-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-10.0.7-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-branding-SLED-7-0.6.7.80")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"MozillaFirefox-translations-10.0.7-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"libfreebl3-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nspr-4.9.2-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"mozilla-nss-tools-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"libfreebl3-32bit-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.2-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"s390x", reference:"mozilla-nss-32bit-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"libfreebl3-32bit-3.13.6-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.2-0.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:2, cpu:"x86_64", reference:"mozilla-nss-32bit-3.13.6-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
