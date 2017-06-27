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
  script_id(41957);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/21 20:21:20 $");

  script_cve_id("CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");

  script_name(english:"SuSE 11 Security Update : Mozilla (SAT Patch Number 1328)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings the Mozilla XULRunner engine to the 1.9.0.14 stable
release.

It also fixes various security issues :

  - / CVE-2009-30 /. (MFSA 2009-47 / CVE-2009-3069 /
    CVE-2009-3070 / CVE-2009-3071 / CVE-2009-3072 /
    CVE-2009-3073)

  - Mozilla developers and community members identified and
    fixed several stability bugs in the browser engine used
    in Firefox and other Mozilla-based products. Some of
    these crashes showed evidence of memory corruption under
    certain circumstances and we presume that with enough
    effort at least some of these could be exploited to run
    arbitrary code. (CVE-2009-3075)

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
    value:"https://bugzilla.novell.com/show_bug.cgi?id=534458"
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
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1328.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-gnomevfs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner190-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/01");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-translations-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-32bit-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-32bit-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"i586", reference:"mozilla-xulrunner190-translations-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-32bit-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-gnomevfs-1.9.0.14-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner190-translations-1.9.0.14-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
