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
  script_id(50874);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/10/25 23:52:01 $");

  script_cve_id("CVE-2010-0654", "CVE-2010-1205", "CVE-2010-1206", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1211", "CVE-2010-1213", "CVE-2010-1214", "CVE-2010-2751", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-2754");

  script_name(english:"SuSE 11 / 11.1 Security Update : Mozilla Firefox (SAT Patch Numbers 2780 / 2781)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update brings Mozilla Firefox to the 3.5.11 security release.

It fixes following security issues :

  - Several memory safety bugs in habe been identified in
    the browser engine used in Firefox and other
    Mozilla-based products. Some of these bugs show evidence
    of memory corruption under certain circumstances, and it
    is presumed that with enough effort at least some of
    these could be exploited to run arbitrary code. (MFSA
    2010-34 / CVE-2010-1211)

  - An error in the DOM attribute cloning routine has been
    reported, where under certain circumstances an event
    attribute node can be deleted while another object still
    contains a reference to it. This reference could
    subsequently be accessed, potentially causing the
    execution of attacker controlled memory. (MFSA 2010-35 /
    CVE-2010-1208)

  - An error in Mozilla's implementation of NodeIterator has
    been reported which can be used to create a malicious
    NodeFilter to detach nodes from the DOM tree while it is
    being traversed. The use of a detached and subsequently
    deleted node could result in the execution of attacker
    controlled memory. (MFSA 2010-36 / CVE-2010-1209)

  - An error in the code used to store the names and values
    of plugin parameter elements has been found. A malicious
    page could embed plugin content containing a very large
    number of parameter elements which would cause an
    overflow in the integer value counting them. This
    integer is later used for allocation of a memory buffer
    to store the plugin parameters. Under such conditions, a
    buffer that is too small would be created and attacker
    controlled data could be written past the end of the
    buffer, potentially resulting in code execution. (MFSA
    2010-37 / CVE-2010-1214)

  - An array class used to store CSS values contains an
    integer overflow vulnerability. A 16 bit integer used to
    allocate the memory for the array could overflow,
    resulting in too small a buffer being created. When the
    array is later populated with CSS values, data could be
    written past the end of the buffer, potentially
    resulting in the execution of attacker controlled
    memory. (MFSA 2010-39 / CVE-2010-2752)

  - An integer overflow vulnerability in the implementation
    of the XUL <tree> element's selection attribute has been
    found. When the size of a new selection is sufficiently
    large, the integer used in calculating the length of the
    selection can overflow, resulting in a bogus range being
    marked as selected. When adjustSelection is then called
    on the bogus range, the range is deleted, leaving
    dangling references to the ranges. These could be used
    by an attacker to call into deleted memory and run
    arbitrary code on a victim's computer. (MFSA 2010-40 /
    CVE-2010-2753)

  - A buffer overflow in Mozilla graphics code which
    consumes image data processed by libpng has been
    reported. A malformed PNG file could be created causing
    libpng to report an incorrect size of the image. When
    the dimensions of such images are underreported, the
    Mozilla code displaying the graphic will allocate a
    memory buffer to small to contain the image data and
    will wind up writing data past the end of the buffer.
    This could result in the execution of
    attacker-controlled memory. (MFSA 2010-41 /
    CVE-2010-1205)

  - The Web Worker method importScripts can read and parse
    resources from other domains even when the content is
    not valid JavaScript. This is a violation of the
    same-origin policy and could be used by an attacker to
    steal information from other sites. (MFSA 2010-42 /
    CVE-2010-1213)

  - Two methods for spoofing the content of the location bar
    have been reported. The first method works by opening a
    new window containing a resource that responds with an
    HTTP 204 (no content) and then using the reference to
    the new window to insert HTML content into the blank
    document. The second location bar spoofing method does
    not require that the resource opened in a new window
    respond with 204, as long as the opener calls
    window.stop() before the document is loaded. In either
    case a user could be mislead about the correct location
    of the document they are currently viewing. (MFSA
    2010-45 / CVE-2010-1206)

  - The location bar can be spoofed to look like a secure
    page even though the current document was served via
    plaintext. The vulnerability is triggered by a server by
    first redirecting a request for a plaintext resource to
    another resource behind a valid SSL/TLS certificate. A
    second request made to the original plaintext resource
    which is responded to not with a redirect, but with
    JavaScript calling history.back() and history.forward()
    will result in the plaintext resource being displayed
    with a valid SSL/TLS badge in the location bar. (MFSA
    2010-45 / CVE-2010-2751)

  - Data can be read across domains by injecting bogus CSS
    selectors into a target site and then retrieving the
    data using JavaScript APIs. If an attacker can inject
    opening and closing portions of a CSS selector into
    points A and B of a target page, then the region between
    the two injection points becomes readable to JavaScript
    through, for example, the getComputedStyle() API. (MFSA
    2010-46 / CVE-2010-0654)

  - Potentially sensitive URL parameters can be leaked
    across domains upon script errors when the script
    filename and line number is included in the error
    message. (MFSA 2010-47 / CVE-2010-2754)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=622506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1205.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1206.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1208.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1209.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1211.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1213.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1214.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2751.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2753.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2754.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2780 / 2781 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(94);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/22");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaFirefox-translations-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaFirefox-translations-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"MozillaFirefox-translations-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"MozillaFirefox-translations-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-gnomevfs-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-translations-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"MozillaFirefox-translations-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"MozillaFirefox-translations-3.5.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-gnomevfs-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"mozilla-xulrunner191-translations-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"mozilla-xulrunner191-32bit-1.9.1.11-0.1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
