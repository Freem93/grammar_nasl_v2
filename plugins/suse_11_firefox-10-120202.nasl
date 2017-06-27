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
  script_id(57838);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/01 13:32:21 $");

  script_cve_id("CVE-2011-3659", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0444", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449", "CVE-2012-0450");

  script_name(english:"SuSE 11.1 Security Update : MozillaFirefox (SAT Patch Number 5754)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides Mozilla Firefox 10, which provides many fixes,
security and feature enhancements.

For a detailed list, please have a look at

http://www.mozilla.org/en-US/firefox/10.0/releasenotes/

and

http://www.mozilla.org/de/firefox/features/

The following security issues have been fixed in this update :

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2012-01 / CVE-2012-0442 / CVE-2012-0443)

  - Alex Dvorov reported that an attacker could replace a
    sub-frame in another domain's document by using the name
    attribute of the sub-frame as a form submission target.
    This can potentially allow for phishing attacks against
    users and violates the HTML5 frame navigation policy.
    (MFSA 2012-03 / CVE-2012-0445)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that removed child
    nodes of nsDOMAttribute can be accessed under certain
    circumstances because of a premature notification of
    AttributeChildRemoved. This use-after-free of the child
    nodes could possibly allow for for remote code
    execution. (MFSA 2012-04 / CVE-2011-3659)

  - Mozilla security researcher moz_bug_r_a4 reported that
    frame scripts bypass XPConnect security checks when
    calling untrusted objects. This allows for cross-site
    scripting (XSS) attacks through web pages and Firefox
    extensions. The fix enables the Script Security Manager
    (SSM) to force security checks on all frame scripts.
    (MFSA 2012-05 / CVE-2012-0446)

  - Mozilla developer Tim Abraldes reported that when
    encoding images as image/vnd.microsoft.icon the
    resulting data was always a fixed size, with
    uninitialized memory appended as padding beyond the size
    of the actual image. This is the result of
    mImageBufferSize in the encoder being initialized with a
    value different than the size of the source image. There
    is the possibility of sensitive data from uninitialized
    memory being appended to a PNG image when converted fron
    an ICO format image. This sensitive data may then be
    disclosed in the resulting image. ((MFSA 2012-06)
    http://www.mozilla.org/security/announce/2012/mfsa2012-0
    6.html], [CVE-2012-0447)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative the possibility of
    memory corruption during the decoding of Ogg Vorbis
    files. This can cause a crash during decoding and has
    the potential for remote code execution. (MFSA 2012-07 /
    CVE-2012-0444)

  - Security researchers Nicolas Gregoire and Aki Helin
    independently reported that when processing a malformed
    embedded XSLT stylesheet, Firefox can crash due to a
    memory corruption. While there is no evidence that this
    is directly exploitable, there is a possibility of
    remote code execution. (MFSA 2012-08 / CVE-2012-0449)

  - magicant starmen reported that if a user chooses to
    export their Firefox Sync key the 'Firefox Recovery
    Key.html' file is saved with incorrect permissions,
    making the file contents potentially readable by other
    users on Linux and OS X systems. (MFSA 2012-09 /
    CVE-2012-0450)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-01.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-03.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-04.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-05.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-06.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-08.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2012/mfsa2012-09.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=742826"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3659.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0443.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0444.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0445.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0446.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0447.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0449.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0450.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5754.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:beagle-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mhtml-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-kde4-integration");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-10.0-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-branding-SLED-7-0.6.7.7")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-translations-10.0-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"beagle-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"beagle-evolution-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"beagle-firefox-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"beagle-gui-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"beagle-lang-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"flash-player-11.1.102.55-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mhtml-firefox-0.5-1.45.7")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-kde4-integration-0.6.3-5.6.5")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-10.0-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-branding-SLED-7-0.6.7.7")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-translations-10.0-0.3.2")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"beagle-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"beagle-evolution-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"beagle-firefox-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"beagle-gui-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"beagle-lang-0.3.8-56.44.45.6")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"flash-player-11.1.102.55-0.13.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mhtml-firefox-0.5-1.45.7")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-kde4-integration-0.6.3-5.6.5")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-10.0-0.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-branding-SLED-7-0.6.7.7")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-translations-10.0-0.3.2")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-kde4-integration-0.6.3-5.6.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
