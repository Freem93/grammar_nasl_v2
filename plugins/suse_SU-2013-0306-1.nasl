#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2013:0306-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83574);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id("CVE-2012-5829", "CVE-2013-0743", "CVE-2013-0744", "CVE-2013-0745", "CVE-2013-0746", "CVE-2013-0747", "CVE-2013-0748", "CVE-2013-0749", "CVE-2013-0750", "CVE-2013-0751", "CVE-2013-0752", "CVE-2013-0753", "CVE-2013-0754", "CVE-2013-0755", "CVE-2013-0756", "CVE-2013-0757", "CVE-2013-0758", "CVE-2013-0759", "CVE-2013-0760", "CVE-2013-0762", "CVE-2013-0763", "CVE-2013-0764", "CVE-2013-0766", "CVE-2013-0768", "CVE-2013-0769", "CVE-2013-0770", "CVE-2013-0771");
  script_bugtraq_id(56607, 56636, 57185, 57193, 57194, 57197, 57198, 57199, 57203, 57204, 57205, 57207, 57209, 57211, 57213, 57215, 57217, 57218, 57228, 57232, 57234, 57235, 57236, 57238, 57240, 57241, 57244, 57258, 57260);

  script_name(english:"SUSE SLES10 Security Update : Mozilla Firefox (SUSE-SU-2013:0306-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is updated to the 10.0.12ESR version.

This is a roll-up update for LTSS.

It fixes a lot of security issues and bugs. 10.0.12ESR fixes
specifically :

MFSA 2013-01: Mozilla developers identified and fixed several memory
safety bugs in the browser engine used in Firefox and other
Mozilla-based products. Some of these bugs showed evidence of memory
corruption under certain circumstances, and we presume that with
enough effort at least some of these could be exploited to run
arbitrary code.

Christoph Diehl, Christian Holler, Mats Palmgren, and Chiaki
Ishikawa reported memory safety problems and crashes that
affect Firefox ESR 10, Firefox ESR 17, and Firefox 17.
(CVE-2013-0769)

Bill Gianopoulos, Benoit Jacob, Christoph Diehl, Christian
Holler, Gary Kwong, Robert O'Callahan, and Scoobidiver
reported memory safety problems and crashes that affect
Firefox ESR 17 and Firefox 17. (CVE-2013-0749)

Jesse Ruderman, Christian Holler, Julian Seward, and
Scoobidiver reported memory safety problems and crashes that
affect Firefox 17. (CVE-2013-0770)

MFSA 2013-02: Security researcher Abhishek Arya (Inferno) of
the Google Chrome Security Team discovered a series
critically rated of use-after-free, out of bounds read, and
buffer overflow issues using the Address Sanitizer tool in
shipped software. These issues are potentially exploitable,
allowing for remote code execution. We would also like to
thank Abhishek for reporting three additional
user-after-free and out of bounds read flaws introduced
during Firefox development that were fixed before general
release.

The following issue has been fixed in Firefox 18 :

   - Global-buffer-overflow in
    CharDistributionAnalysis::HandleOneChar (CVE-2013-0760)

    The following issues has been fixed in Firefox 18, ESR
    17.0.1, and ESR 10.0.12 :

   - Heap-use-after-free in imgRequest::OnStopFrame
    (CVE-2013-0762)
  - Heap-use-after-free in ~nsHTMLEditRules (CVE-2013-0766)
  - Out of bounds read in
    nsSVGPathElement::GetPathLengthScale (CVE-2013-0763)
  - Heap-buffer-overflow in
    gfxTextRun::ShrinkToLigatureBoundaries (CVE-2013-0771)

    The following issue has been fixed in Firefox 18 and in
    the earlier ESR 10.0.11 release :

   - Heap-buffer-overflow in nsWindow::OnExposeEvent
    (CVE-2012-5829) MFSA 2013-03: Security researcher
    miaubiz used the Address Sanitizer tool to discover a
    buffer overflow in Canvas when specific bad height and
    width values were given through HTML. This could lead to
    a potentially exploitable crash. (CVE-2013-0768)

    Miaubiz also found a potentially exploitable crash when
    2D and 3D content was mixed which was introduced during
    Firefox development and fixed before general release.

    MFSA 2013-04: Security researcher Masato Kinugawa found
    a flaw in which the displayed URL values within the
    addressbar can be spoofed by a page during loading. This
    allows for phishing attacks where a malicious page can
    spoof the identify of another site. (CVE-2013-0759)

    MFSA 2013-05: Using the Address Sanitizer tool, security
    researcher Atte Kettunen from OUSPG discovered that the
    combination of large numbers of columns and column
    groups in a table could cause the array containing the
    columns during rendering to overwrite itself. This can
    lead to a user-after-free causing a potentially
    exploitable crash. (CVE-2013-0744)

    MFSA 2013-06: Mozilla developer Wesley Johnston reported
    that when there are two or more iframes on the same HTML
    page, an iframe is able to see the touch events and
    their targets that occur within the other iframes on the
    page. If the iframes are from the same origin, they can
    also access the properties and methods of the targets of
    other iframes but same-origin policy (SOP) restricts
    access across domains. This allows for information
    leakage and possibilities for cross-site scripting (XSS)
    if another vulnerability can be used to get around SOP
    restrictions. (CVE-2013-0751)

    MFSA 2013-07: Mozilla community member Jerry Baker
    reported a crashing issue found through Thunderbird when
    downloading messages over a Secure Sockets Layer (SSL)
    connection. This was caused by a bug in the networking
    code assuming that secure connections were entirely
    handled on the socket transport thread when they can
    occur on a variety of threads. The resulting crash was
    potentially exploitable. (CVE-2013-0764)

    MFSA 2013-08: Mozilla developer Olli Pettay discovered
    that the AutoWrapperChanger class fails to keep some
    JavaScript objects alive during garbage collection. This
    can lead to an exploitable crash allowing for arbitrary
    code execution. (CVE-2013-0745)

    MFSA 2013-09: Mozilla developer Boris Zbarsky reported
    reported a problem where jsval-returning quickstubs fail
    to wrap their return values, causing a compartment
    mismatch. This mismatch can cause garbage collection to
    occur incorrectly and lead to a potentially exploitable
    crash. (CVE-2013-0746)

    MFSA 2013-10: Mozilla security researcher Jesse Ruderman
    reported that events in the plugin handler can be
    manipulated by web content to bypass same-origin policy
    (SOP) restrictions. This can allow for clickjacking on
    malicious web pages. (CVE-2013-0747)

    MFSA 2013-11: Mozilla security researcher Jesse Ruderman
    discovered that using the toString function of XBL
    objects can lead to inappropriate information leakage by
    revealing the address space layout instead of just the
    ID of the object. This layout information could
    potentially be used to bypass ASLR and other security
    protections. (CVE-2013-0748)

    MFSA 2013-12: Security researcher pa_kt reported a flaw
    via TippingPoint's Zero Day Initiative that an integer
    overflow is possible when calculating the length for a
    JavaScript string concatenation, which is then used for
    memory allocation. This results in a buffer overflow,
    leading to a potentially exploitable memory corruption.
    (CVE-2013-0750)

    MFSA 2013-13: Security researcher Sviatoslav Chagaev
    reported that when using an XBL file containing multiple
    XML bindings with SVG content, a memory corruption can
    occur. In concern with remote XUL, this can lead to an
    exploitable crash. (CVE-2013-0752)

    MFSA 2013-14: Security researcher Mariusz Mlynski
    reported that it is possible to change the prototype of
    an object and bypass Chrome Object Wrappers (COW) to
    gain access to chrome privileged functions. This could
    allow for arbitrary code execution. (CVE-2013-0757)

    MFSA 2013-15: Security researcher Mariusz Mlynski
    reported that it is possible to open a chrome privileged
    web page through plugin objects through interaction with
    SVG elements. This could allow for arbitrary code
    execution. (CVE-2013-0758)

    MFSA 2013-16: Security researcher regenrecht reported,
    via TippingPoint's Zero Day Initiative, a use-after-free
    in XMLSerializer by the exposing of serializeToStream to
    web content. This can lead to arbitrary code execution
    when exploited. (CVE-2013-0753)

    MFSA 2013-17: Security researcher regenrecht reported,
    via TippingPoint's Zero Day Initiative, a use-after-free
    within the ListenerManager when garbage collection is
    forced after data in listener objects have been
    allocated in some circumstances. This results in a
    use-after-free which can lead to arbitrary code
    execution. (CVE-2013-0754)

    MFSA 2013-18: Security researcher regenrecht reported,
    via TippingPoint's Zero Day Initiative, a use-after-free
    using the domDoc pointer within Vibrate library. This
    can lead to arbitrary code execution when exploited.
    (CVE-2013-0755)

    MFSA 2013-19: Security researcher regenrecht reported,
    via TippingPoint's Zero Day Initiative, a garbage
    collection flaw in JavaScript Proxy objects. This can
    lead to a use-after-free leading to arbitrary code
    execution. (CVE-2013-0756)

    MFSA 2013-20: Google reported to Mozilla that TURKTRUST,
    a certificate authority in Mozilla's root program, had
    mis-issued two intermediate certificates to customers.
    The issue was not specific to Firefox but there was
    evidence that one of the certificates was used for
    man-in-the-middle (MITM) traffic management of domain
    names that the customer did not legitimately own or
    control. This issue was resolved by revoking the trust
    for these specific mis-issued certificates.
    (CVE-2013-0743)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=8d645904d43fff2d5195e42ae81f6d59
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e596b06"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/666101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/681836"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/684069"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/712248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/769762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/796895"
  );
  # https://www.suse.com/support/update/announcement/2013/suse-su-20130306-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5acd6ef0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected Mozilla Firefox packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 17.0.1 Flash Privileged Code Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox3-cairo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox3-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:firefox3-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/18");
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
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox3-cairo-32bit-1.2.4-0.8.5")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox3-gtk2-32bit-2.10.6-0.12.21")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"firefox3-pango-32bit-1.14.5-0.12.178")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.9.4-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"x86_64", reference:"mozilla-nss-32bit-3.14.1-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox3-cairo-32bit-1.2.4-0.8.5")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox3-gtk2-32bit-2.10.6-0.12.21")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"firefox3-pango-32bit-1.14.5-0.12.178")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-nspr-32bit-4.9.4-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", cpu:"s390x", reference:"mozilla-nss-32bit-3.14.1-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox3-cairo-1.2.4-0.8.5")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox3-gtk2-2.10.6-0.12.21")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"firefox3-pango-1.14.5-0.12.178")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nspr-4.9.4-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nspr-devel-4.9.4-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nss-3.14.1-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nss-devel-3.14.1-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"mozilla-nss-tools-3.14.1-0.6.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"MozillaFirefox-10.0.12-0.6.3")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"MozillaFirefox-branding-SLED-7-0.8.46")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"MozillaFirefox-translations-10.0.12-0.6.3")) flag++;


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
