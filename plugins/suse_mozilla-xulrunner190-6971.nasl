#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49901);
  script_version ("$Revision: 1.8 $");
  script_cvs_date("$Date: 2012/06/14 20:02:12 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-0173", "CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-0178", "CVE-2010-0179", "CVE-2010-0181", "CVE-2010-0182");

  script_name(english:"SuSE 10 Security Update : Mozilla XULrunner (ZYPP Patch Number 6971)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla XULRunner was updated to version 1.9.0.19 fixing lots of bugs
and security issues.

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
    option elements are inserted into a XUL tree optgroup.
    In certain cases, the number of references to an option
    element is under-counted so that when the element is
    deleted, a live pointer to its old location is kept
    around and may later be used. An attacker could
    potentially use these conditions to run arbitrary code
    on a victim's computer. (MFSA 2010-18 / CVE-2010-0176)

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
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6971.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, reference:"mozilla-xulrunner190-translations-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLED10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"mozilla-xulrunner190-translations-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.19-0.4.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.19-0.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
