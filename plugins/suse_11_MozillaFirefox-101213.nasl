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
  script_id(51591);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2010-0179", "CVE-2010-3766", "CVE-2010-3767", "CVE-2010-3768", "CVE-2010-3769", "CVE-2010-3770", "CVE-2010-3771", "CVE-2010-3772", "CVE-2010-3773", "CVE-2010-3774", "CVE-2010-3775", "CVE-2010-3776", "CVE-2010-3777", "CVE-2010-3778");

  script_name(english:"SuSE 11.1 Security Update : Mozilla Firefox (SAT Patch Number 3693)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox 3.6 was updated to update 3.6.13 fixing several
security issues.

  - Mozilla developers identified and fixed several memory
    safety bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these bugs showed
    evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2010-74)

    Jesee Ruderman, Andreas Gal, Nils, and Brian Hackett
    reported memory safety problems that affected Firefox
    3.6 and Firefox 3.5. (CVE-2010-3776)

    Igor Bukanov reported a memory safety problem that was
    fixed in Firefox 3.6 only. (CVE-2010-3777)

    Jesse Ruderman reported a crash which affected Firefox
    3.5 only. (CVE-2010-3778)

  - Dirk Heinrich reported that on Windows platforms when
    document.write() was called with a very long string a
    buffer overflow was caused in line breaking routines
    attempting to process the string for display. Such cases
    triggered an invalid read past the end of an array
    causing a crash which an attacker could potentially use
    to run arbitrary code on a victim's computer. (MFSA
    2010-75 / CVE-2010-3769)

  - Security researcher echo reported that a web page could
    open a window with an about:blank location and then
    inject an. (MFSA 2010-76 / CVE-2010-3771)

    element into that page which upon submission would
    redirect to a chrome: document. The effect of this
    defect was that the original page would wind up with a
    reference to a chrome-privileged object, the opened
    window, which could be leveraged for privilege
    escalation attacks.

    Mozilla security researcher moz_bug_r_a4 provided
    proof-of-concept code demonstrating how the above
    vulnerability could be used to run arbitrary code with
    chrome privileges.

  - Security researcher wushi of team509 reported that when
    a XUL tree had an HTML element nested inside a element
    then code attempting to display content in the XUL tree
    would incorrectly treat the element as a parent node to
    tree content underneath it resulting in incorrect
    indexes being calculated for the child content. These
    incorrect indexes were used in subsequent array
    operations which resulted in writing data past the end
    of an allocated buffer. An attacker could use this issue
    to crash a victim's browser and run arbitrary code on
    their machine. (MFSA 2010-77 / CVE-2010-3772)

  - Mozilla added the OTS font sanitizing library to prevent
    downloadable fonts from exposing vulnerabilities in the
    underlying OS font code. This library mitigates against
    several issues independently reported by Red Hat
    Security Response Team member Marc Schoenefeld and
    Mozilla security researcher Christoph Diehl. (MFSA
    2010-78 / CVE-2010-3768)

  - Security researcher Gregory Fleischer reported that when
    a Java LiveConnect script was loaded via a data: URL
    which redirects via a meta refresh, then the resulting
    plugin object was created with the wrong security
    principal and thus received elevated privileges such as
    the abilities to read local files, launch processes, and
    create network connections. (MFSA 2010-79 /
    CVE-2010-3775)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that a nsDOMAttribute
    node can be modified without informing the iterator
    object responsible for various DOM traversals. This flaw
    could lead to a inconsistent state where the iterator
    points to an object it believes is part of the DOM but
    actually points to some other object. If such an object
    had been deleted and its memory reclaimed by the system,
    then the iterator could be used to call into
    attacker-controlled memory. (MFSA 2010-80 /
    CVE-2010-3766)

  - Security researcher regenrecht reported via
    TippingPoint's Zero Day Initiative that JavaScript
    arrays were vulnerable to an integer overflow
    vulnerability. The report demonstrated that an array
    could be constructed containing a very large number of
    items such that when memory was allocated to store the
    array items, the integer value used to calculate the
    buffer size would overflow resulting in too small a
    buffer being allocated. Subsequent use of the array
    object could then result in data being written past the
    end of the buffer and causing memory corruption. (MFSA
    2010-81 / CVE-2010-3767)

  - Mozilla security researcher moz_bug_r_a4 reported that
    the fix for CVE-2010-0179 could be circumvented
    permitting the execution of arbitrary JavaScript with
    chrome privileges. (MFSA 2010-82 / CVE-2010-3773)

  - Google security researcher Michal Zalewski reported that
    when a window was opened to a site resulting in a
    network or certificate error page, the opening site
    could access the document inside the opened window and
    inject arbitrary content. An attacker could use this bug
    to spoof the location bar and trick a user into thinking
    they were on a different site than they actually were.
    (MFSA 2010-83 / CVE-2010-3774)

  - Security researchers Yosuke Hasegawa and Masatoshi
    Kimura reported that the x-mac-arabic, x-mac-farsi and
    x-mac-hebrew character encodings are vulnerable to XSS
    attacks due to some characters being converted to angle
    brackets when displayed by the rendering engine. Sites
    using these character encodings would thus be
    potentially vulnerable to script injection attacks if
    their script filtering code fails to strip out these
    specific characters. (MFSA 2010-84 / CVE-2010-3770)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-74.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-75.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-76.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-77.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-78.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-79.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-80.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-81.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-82.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-83.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-84.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=657016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3766.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3768.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3769.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3770.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3771.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3772.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3773.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3774.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3775.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3776.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3777.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-3778.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 3693.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-gnome-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:mozilla-xulrunner192-translations-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-3.6.13-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-translations-3.6.13-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-gnome-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner192-translations-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-3.6.13-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-translations-3.6.13-0.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-gnome-32bit-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-translations-32bit-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-3.6.13-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-translations-3.6.13-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-gnome-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner192-translations-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-xulrunner192-32bit-1.9.2.13-1.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner192-32bit-1.9.2.13-1.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
