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
  script_id(50873);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2008-5913", "CVE-2010-0183", "CVE-2010-1121", "CVE-2010-1125", "CVE-2010-1196", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1201", "CVE-2010-1202", "CVE-2010-1203");

  script_name(english:"SuSE 11 / 11.1 Security Update : Mozilla Firefox (SAT Patch Numbers 2608 / 2609)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox has been updated to version 3.5.10, fixing various
bugs and security issues.

  - Security researcher Amit Klein reported that it was
    possible to reverse engineer the value used to seed
    Math.random(). Since the pseudo-random number generator
    was only seeded once per browsing session, this seed
    value could be used as a unique token to identify and
    track users across different web sites. (MFSA 2010-33/
    CVE-2008-5913)

  - Security researcher Ilja van Sprundel of IOActive
    reported that the Content-Disposition: attachment HTTP
    header was ignored when `Content-Type: multipart` was
    also present. This issue could potentially lead to XSS
    problems in sites that allow users to upload arbitrary
    files and specify a content type but rely on
    Content-Disposition: attachment to prevent the content
    from being displayed inline. (MFSA 2010-32/
    CVE-2010-1197)

  - Google security researcher Michal Zalewski reported that
    focus() could be used to change a user's cursor focus
    while they are typing, potentially directing their
    keyboard input to an unintended location. This behaviour
    was also present across origins when content from one
    domain was embedded within another via an iframe. A
    malicious web page could use this behaviour to steal
    keystrokes from a victim while they were typing
    sensitive information such as a password. (MFSA 2010-31/
    CVE-2010-1125)

  - Security researcher Martin Barbella reported via
    TippingPoint's Zero Day Initiative that an XSLT node
    sorting routine contained an integer overflow
    vulnerability. In cases where one of the nodes to be
    sorted contained a very large text value, the integer
    used to allocate a memory buffer to store its value
    would overflow, resulting in too small a buffer being
    created. An attacker could use this vulnerability to
    write data past the end of the buffer, causing the
    browser to crash and potentially running arbitrary code
    on a victim's computer. (MFSA 2010-30/ CVE-2010-1199)

  - Security researcher Nils of MWR InfoSecurity reported
    that the routine for setting the text value for certain
    types of DOM nodes contained an integer overflow
    vulnerability. When a very long string was passed to
    this routine, the integer value used in creating a new
    memory buffer to hold the string would overflow,
    resulting in too small a buffer being allocated. An
    attacker could use this vulnerability to write data past
    the end of the buffer, causing a crash and potentially
    running arbitrary code on a victim's computer. (MFSA
    2010-29/ CVE-2010-1196)

  - Microsoft Vulnerability Research reported that two
    plugin instances could interact in a way in which one
    plugin gets a reference to an object owned by a second
    plugin and continues to hold that reference after the
    second plugin is unloaded and its object is destroyed.
    In these cases, the first plugin would contain a pointer
    to freed memory which, if accessed, could be used by an
    attacker to execute arbitrary code on a victim's
    computer. (MFSA 2010-28/ CVE-2010-1198)

  - Security researcher Wushi of Team509 reported that the
    frame construction process for certain types of menus
    could result in a menu containing a pointer to a
    previously freed menu item. During the cycle collection
    process, this freed item could be accessed, resulting in
    the execution of a section of code potentially
    controlled by an attacker. (MFSA 2010-27/ CVE-2010-0183)

  - Mozilla developers identified and fixed several
    stability bugs in the browser engine used in Firefox and
    other Mozilla-based products. Some of these crashes
    showed evidence of memory corruption under certain
    circumstances, and we presume that with enough effort at
    least some of these could be exploited to run arbitrary
    code. (MFSA 2010-26/ CVE-2010-1200 / CVE-2010-1201 /
    CVE-2010-1202 / CVE-2010-1203)

  - A memory corruption flaw leading to code execution was
    reported by security researcher Nils of MWR InfoSecurity
    during the 2010 Pwn2Own contest sponsored by
    TippingPoint's Zero Day Initiative. By moving DOM nodes
    between documents, Nils found a case where the moved
    node incorrectly retained its old scope. If garbage
    collection could be triggered at the right time then
    Firefox would later use this freed object. The exploit
    only affects Firefox 3.6 and not earlier versions.
    Updated (June 22, 2010): Firefox 3.5, SeaMonkey 2.0, and
    Thunderbird 3.0 based on earlier versions of the browser
    engine were patched just in case there is an alternate
    way of triggering the underlying flaw. (MFSA 2010-25/
    CVE-2010-1121)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-25.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-26.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-27.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-28.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-29.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-30.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-32.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2010/mfsa2010-33.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603356"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5913.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1121.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1125.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1198.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1199.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1201.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1203.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2608 / 2609 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/28");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-translations-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-translations-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-translations-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-translations-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-translations-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-xulrunner191-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-translations-3.5.10-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-translations-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-xulrunner191-32bit-1.9.1.10-1.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.10-1.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
