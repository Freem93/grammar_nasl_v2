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
  script_id(50872);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0173", "CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179", "CVE-2010-0181", "CVE-2010-0182");

  script_name(english:"SuSE 11 Security Update : MozillaFirefox, MozillaFirefox-branding-upstream, etc (SAT Patch Number 2254)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox was updated to version 3.5.9 fixing lots of bugs and
security issues.

The following security issues were fixed :

  - Mozilla developers identified and fixed several
    stability bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these crashes
    showed evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2010-16)

References

Martijn Wargers, Josh Soref, and Jesse Ruderman reported crashes in
the browser engine that affected Firefox 3.5 and Firefox 3.6.
(CVE-2010-0173)

Jesse Ruderman and Ehsan Akhgari reported crashes that affected all
supported versions of the browser engine. (CVE-2010-0174)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that a select event
    handler for XUL tree items could be called after the
    tree item was deleted. This results in the execution of
    previously freed memory which an attacker could use to
    crash a victim's browser and run arbitrary code on the
    victim's computer. (MFSA 2010-17 / CVE-2010-0175)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative an error in the way
    elements are inserted into a XUL tree optgroup. In
    certain cases, the number of references to an element is
    under-counted so that when the element is deleted, a
    live pointer to its old location is kept around and may
    later be used. An attacker could potentially use these
    conditions to run arbitrary code on a victim's computer.
    (MFSA 2010-18 / CVE-2010-0176)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative an error in the
    implementation of the window.navigator.plugins object.
    When a page reloads, the plugins array would reallocate
    all of its members without checking for existing
    references to each member. This could result in the
    deletion of objects for which valid pointers still
    exist. An attacker could use this vulnerability to crash
    a victim's browser and run arbitrary code on the
    victim's machine. (MFSA 2010-19 / CVE-2010-0177)

  - Security researcher Paul Stone reported that a browser
    applet could be used to turn a simple mouse click into a
    drag-and-drop action, potentially resulting in the
    unintended loading of resources in a user's browser.
    This behavior could be used twice in succession to first
    load a privileged chrome: URL in a victim's browser,
    then load a malicious javascript: URL on top of the same
    document resulting in arbitrary script execution with
    chrome privileges. (MFSA 2010-20 / CVE-2010-0178)

  - Mozilla security researcher moz_bug_r_a4 reported that
    the XMLHttpRequestSpy module in the Firebug add-on was
    exposing an underlying chrome privilege escalation
    vulnerability. When the XMLHttpRequestSpy object was
    created, it would attach various properties of itself to
    objects defined in web content, which were not being
    properly wrapped to prevent their exposure to chrome
    privileged objects. This could result in an attacker
    running arbitrary JavaScript on a victim's machine,
    though it required the victim to have Firebug installed,
    so the overall severity of the issue was determined to
    be High. (MFSA 2010-21 / CVE-2010-0179)

  - Mozilla developers added support in the Network Security
    Services module for preventing a type of
    man-in-the-middle attack against TLS using forced
    renegotiation. (MFSA 2010-22 / CVE-2009-3555)

Note that to benefit from the fix, Firefox 3.6 and Firefox 3.5 users
will need to set their security.ssl.require_safe_negotiation
preference to true. Firefox 3 does not contain the fix for this issue.

  - phpBB developer Henry Sudhof reported that when an image
    tag points to a resource that redirects to a mailto:
    URL, the external mail handler application is launched.
    This issue poses no security threat to users but could
    create an annoyance when browsing a site that allows
    users to post arbitrary images. (MFSA 2010-23 /
    CVE-2010-0181)

  - Mozilla community member Wladimir Palant reported that
    XML documents were failing to call certain security
    checks when loading new content. This could result in
    certain resources being loaded that would otherwise
    violate security policies set by the browser or
    installed add-ons. (MFSA 2010-24 / CVE-2010-0182)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-16.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-17.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-18.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-19.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-20.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-21.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-22.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-23.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-24.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=586567"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0173.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0174.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0175.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0176.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0177.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0178.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0182.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2254.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner191-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-translations-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"MozillaFirefox-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-translations-3.5.9-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.9-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.9-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
