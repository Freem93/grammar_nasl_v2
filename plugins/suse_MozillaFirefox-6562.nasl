#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(44934);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/22 20:42:27 $");

  script_cve_id("CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");

  script_name(english:"SuSE 10 Security Update : Mozilla Firefox (ZYPP Patch Number 6562)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings the Mozilla Firefox 3.5 webbrowser to version
3.5.3, the Mozilla XULRunner 1.9.0 engine to the 1.9.0.14 stable
release, and the Mozilla XULRunner 1.9.1 engine to the 1.9.1.3 stable
release.

It also fixes various security issues :

  - Mozilla developers and community members identified and
    fixed several stability bugs in the browser engine used
    in Firefox and other Mozilla-based products. Some of
    these crashes showed evidence of memory corruption under
    certain circumstances and we presume that with enough
    effort at least some of these could be exploited to run
    arbitrary code. (MFSA 2009-47 / CVE-2009-3069 /
    CVE-2009-3070 / CVE-2009-3071 / CVE-2009-3072 /
    CVE-2009-3073 / CVE-2009-3074 / CVE-2009-3075)

  - Mozilla security researcher Jesse Rudermanreported that
    when security modules were added or removed via
    pkcs11.addmodule or pkcs11.deletemodule, the resulting
    dialog was not sufficiently informative. Without
    sufficient warning, an attacker could entice a victim to
    install a malicious PKCS11 module and affect the
    cryptographic integrity of the victim's browser.
    Security researcher Dan Kaminsky reported that this
    issue had not been fixed in Firefox 3.0 and that under
    certain circumstances pkcs11 modules could be installed
    from a remote location. Firefox 3.5 releases are not
    affected. (MFSA 2009-48 / CVE-2009-3076)

  - An anonymous security researcher, via TippingPoint's
    Zero Day Initiative, reported that the columns of a XUL
    tree element could be manipulated in a particular way
    which would leave a pointer owned by the column pointing
    to freed memory. An attacker could potentially use this
    vulnerability to crash a victim's browser and run
    arbitrary code on the victim's computer. (MFSA 2009-49 /
    CVE-2009-3077)

  - Security researcher Juan Pablo Lopez Yacubian reported
    that the default Windows font used to render the
    locationbar and other text fields was improperly
    displaying certain Unicode characters with tall
    line-height. In such cases the tall line-height would
    cause the rest of the text in the input field to be
    scrolled vertically out of view. An attacker could use
    this vulnerability to prevent a user from seeing the URL
    of a malicious site. Corrie Sloot also independently
    reported this issue to Mozilla. (MFSA 2009-50 /
    CVE-2009-3078)

  - Mozilla security researcher moz_bug_r_a4 reported that
    the BrowserFeedWriter could be leveraged to run
    JavaScript code from web content with elevated
    privileges. Using this vulnerability, an attacker could
    construct an object containing malicious JavaScript and
    cause the FeedWriter to process the object, running the
    malicious code with chrome privileges. Thunderbird does
    not support the BrowserFeedWriter object and is not
    vulnerable in its default configuration. Thunderbird
    might be vulnerable if the user has installed any add-on
    which adds a similarly implemented feature and then
    enables JavaScript in mail messages. This is not the
    default setting and we strongly discourage users from
    running JavaScript in mail. (MFSA 2009-51 /
    CVE-2009-3079)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-47.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-48.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-49.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-50.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-51.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3069.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3071.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3072.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3075.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3078.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3079.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6562.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-3.5.3-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-branding-SLED-3.5-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"MozillaFirefox-translations-3.5.3-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner190-translations-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner191-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, reference:"mozilla-xulrunner191-translations-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-3.5.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-branding-SLED-3.5-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"MozillaFirefox-translations-3.5.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-gnomevfs-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner190-translations-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner191-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, reference:"mozilla-xulrunner191-translations-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.14-0.5.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.3-1.4.2")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.3-1.4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
