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
  script_id(41357);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-1194", "CVE-2009-2462", "CVE-2009-2463", "CVE-2009-2464", "CVE-2009-2465", "CVE-2009-2466", "CVE-2009-2467", "CVE-2009-2469", "CVE-2009-2471", "CVE-2009-2472");

  script_name(english:"SuSE 11 Security Update : MozillaFirefox (SAT Patch Number 1134)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Mozilla Firefox 3.0.12 release fixes various bugs and some
critical security issues.

  - Mozilla developers and community members identified and
    fixed several stability bugs in the browser engine used
    in Firefox and other Mozilla-based products. Some of
    these crashes showed evidence of memory corruption under
    certain circumstances and we presume that with enough
    effort at least some of these could be exploited to run
    arbitrary code. (MFSA 2009-34 / CVE-2009-2462 /
    CVE-2009-2463 / CVE-2009-2464 / CVE-2009-2465 /
    CVE-2009-2466)

  - Security researcher Attila Suszter reported that when a
    page contains a Flash object which presents a slow
    script dialog, and the page is navigated while the
    dialog is still visible to the user, the Flash plugin is
    unloaded resulting in a crash due to a call to the
    deleted object. This crash could potentially be used by
    an attacker to run arbitrary code on a victim's
    computer. (MFSA 2009-35 / CVE-2009-2467)

  - oCERT security researcher Will Drewry reported a series
    of heap and integer overflow vulnerabilities which
    independently affected multiple font glyph rendering
    libraries. On Linux platforms libpango was susceptible
    to the vulnerabilities while on OS X CoreGraphics was
    similarly vulnerable. An attacker could trigger these
    overflows by constructing a very large text run for the
    browser to display. Such an overflow can result in a
    crash which the attacker could potentially use to run
    arbitrary code on a victim's computer. The open source
    nature of Linux meant that Mozilla was able to work with
    the libpango maintainers to implement the correct fix in
    version 1.24 of that system library which was
    distributed with OS security updates. On Mac OS X
    Firefox works around the CoreGraphics flaw by limiting
    the length of text runs passed to the system. (MFSA
    2009-36 / CVE-2009-1194)

  - Security researcher PenPal reported a crash involving a
    SVG element on which a watch function and
    __defineSetter__ function have been set for a particular
    property. The crash showed evidence of memory corruption
    and could potentially be used by an attacker to run
    arbitrary code on a victim's computer. (MFSA 2009-37 /
    CVE-2009-2469)

  - Mozilla developer Blake Kaplan reported that setTimeout,
    when called with certain object parameters which should
    be protected with a XPCNativeWrapper, will fail to keep
    the object wrapped when compiling the new function to be
    executed. If chrome privileged code were to call
    setTimeout using this as an argument, the this object
    will lose its wrapper and could be unsafely accessed by
    chrome code. An attacker could use such vulnerable code
    to run arbitrary JavaScript with chrome privileges.
    (MFSA 2009-39 / CVE-2009-2471)

  - Mozilla security researcher moz_bug_r_a4 reported a
    series of vulnerabilities in which objects that normally
    receive a XPCCrossOriginWrapper are constructed without
    the wrapper. This can lead to cases where JavaScript
    from one website may unsafely access properties of such
    an object which had been set by a different website. A
    malicious website could use this vulnerability to launch
    a XSS attack and run arbitrary JavaScript within the
    context of another site. (MFSA 2009-40 / CVE-2009-2472)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-34.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-35.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-36.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-37.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-39.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-40.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=522109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2462.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2463.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2464.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2465.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2466.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2467.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2472.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1134.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-3.0.12-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-3.0.12-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-translations-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-3.0.12-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-translations-3.0.12-0.1.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-3.0.12-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-translations-3.0.12-0.1.2")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner190-translations-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-xulrunner190-32bit-1.9.0.12-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.12-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
