#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 200805-18.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(32416);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/11 20:08:43 $");

  script_cve_id("CVE-2007-4879", "CVE-2008-0304", "CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241", "CVE-2008-1380");
  script_osvdb_id(38036, 41187, 41215, 41217, 41218, 41220, 41221, 41222, 41223, 41224, 41225, 42056, 42057, 42428, 43226, 43456, 43457, 43458, 43459, 43460, 43461, 43462, 43846, 43847, 43848, 43849, 43857, 43858, 43859, 43860, 43861, 43862, 43863, 43864, 43865, 43866, 43867, 43868, 43869, 43870, 43871, 43872, 43873, 43874, 43875, 43876, 43877, 43878, 44467);
  script_xref(name:"GLSA", value:"200805-18");

  script_name(english:"GLSA-200805-18 : Mozilla products: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-200805-18
(Mozilla products: Multiple vulnerabilities)

    The following vulnerabilities were reported in all mentioned Mozilla
    products:
    Jesse Ruderman, Kai Engert, Martijn Wargers, Mats Palmgren, and Paul
    Nickerson reported browser crashes related to JavaScript methods,
    possibly triggering memory corruption (CVE-2008-0412).
    Carsten Book, Wesley Garland, Igor Bukanov, moz_bug_r_a4, shutdown,
    Philip Taylor, and tgirmann reported crashes in the JavaScript engine,
    possibly triggering memory corruption (CVE-2008-0413).
    David Bloom discovered a vulnerability in the way images are treated by
    the browser when a user leaves a page, possibly triggering memory
    corruption (CVE-2008-0419).
    moz_bug_r_a4, Boris Zbarsky, and Johnny Stenback reported a series of
    privilege escalation vulnerabilities related to JavaScript
    (CVE-2008-1233, CVE-2008-1234, CVE-2008-1235).
    Mozilla developers identified browser crashes caused by the layout and
    JavaScript engines, possibly triggering memory corruption
    (CVE-2008-1236, CVE-2008-1237).
    moz_bug_r_a4 and Boris Zbarsky discovered that pages could escape from
    its sandboxed context and run with chrome privileges, and inject script
    content into another site, violating the browser's same origin policy
    (CVE-2008-0415).
    Gerry Eisenhaur discovered a directory traversal vulnerability when
    using 'flat' addons (CVE-2008-0418).
    Alexey Proskuryakov, Yosuke Hasegawa and Simon Montagu reported
    multiple character handling flaws related to the backspace character,
    the '0x80' character, involving zero-length non-ASCII sequences in
    multiple character sets, that could facilitate Cross-Site Scripting
    attacks (CVE-2008-0416).
    The following vulnerability was reported in Thunderbird and SeaMonkey:
    regenrecht (via iDefense) reported a heap-based buffer overflow when
    rendering an email message with an external MIME body (CVE-2008-0304).
    The following vulnerabilities were reported in Firefox, SeaMonkey and
    XULRunner:
    The fix for CVE-2008-1237 in Firefox 2.0.0.13
    and SeaMonkey 1.1.9 introduced a new crash vulnerability
    (CVE-2008-1380).
    hong and Gregory Fleischer each reported a
    variant on earlier reported bugs regarding focus shifting in file input
    controls (CVE-2008-0414).
    Gynvael Coldwind (Vexillium) discovered that BMP images could be used
    to reveal uninitialized memory, and that this data could be extracted
    using a 'canvas' feature (CVE-2008-0420).
    Chris Thomas reported that background tabs could create a borderless
    XUL pop-up in front of pages in other tabs (CVE-2008-1241).
    oo.rio.oo discovered that a plain text file with a
    'Content-Disposition: attachment' prevents Firefox from rendering
    future plain text files within the browser (CVE-2008-0592).
    Martin Straka reported that the '.href' property of stylesheet DOM
    nodes is modified to the final URI of a 302 redirect, bypassing the
    same origin policy (CVE-2008-0593).
    Gregory Fleischer discovered that under certain circumstances, leading
    characters from the hostname part of the 'Referer:' HTTP header are
    removed (CVE-2008-1238).
    Peter Brodersen and Alexander Klink reported that the browser
    automatically selected and sent a client certificate when SSL Client
    Authentication is requested by a server (CVE-2007-4879).
    Gregory Fleischer reported that web content fetched via the 'jar:'
    protocol was not subject to network access restrictions
    (CVE-2008-1240).
    The following vulnerabilities were reported in Firefox:
    Justin Dolske discovered a CRLF injection vulnerability when storing
    passwords (CVE-2008-0417).
    Michal Zalewski discovered that Firefox does not properly manage a
    delay timer used in confirmation dialogs (CVE-2008-0591).
    Emil Ljungdahl and Lars-Olof Moilanen discovered that a web forgery
    warning dialog is not displayed if the entire contents of a web page
    are in a DIV tag that uses absolute positioning (CVE-2008-0594).
  
Impact :

    A remote attacker could entice a user to view a specially crafted web
    page or email that will trigger one of the vulnerabilities, possibly
    leading to the execution of arbitrary code or a Denial of Service. It
    is also possible for an attacker to trick a user to upload arbitrary
    files when submitting a form, to corrupt saved passwords for other
    sites, to steal login credentials, or to conduct Cross-Site Scripting
    and Cross-Site Request Forgery attacks.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/200805-18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Mozilla Firefox users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-2.0.0.14'
    All Mozilla Firefox binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/mozilla-firefox-bin-2.0.0.14'
    All Mozilla Thunderbird users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-2.0.0.14'
    All Mozilla Thunderbird binary users should upgrade to the latest
    version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=mail-client/mozilla-thunderbird-bin-2.0.0.14'
    All SeaMonkey users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-1.1.9-r1'
    All SeaMonkey binary users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=www-client/seamonkey-bin-1.1.9'
    All XULRunner users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose '>=net-libs/xulrunner-1.8.1.14'
    NOTE: The crash vulnerability (CVE-2008-1380) is currently unfixed in
    the SeaMonkey binary ebuild, as no precompiled packages have been
    released. Until an update is available, we recommend all SeaMonkey
    users to disable JavaScript, use Firefox for JavaScript-enabled
    browsing, or switch to the SeaMonkey source ebuild."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 59, 79, 94, 119, 200, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-firefox-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:mozilla-thunderbird-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:seamonkey-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"www-client/mozilla-firefox-bin", unaffected:make_list("ge 2.0.0.14"), vulnerable:make_list("lt 2.0.0.14"))) flag++;
if (qpkg_check(package:"www-client/seamonkey-bin", unaffected:make_list("ge 1.1.9"), vulnerable:make_list("lt 1.1.9"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird-bin", unaffected:make_list("ge 2.0.0.14"), vulnerable:make_list("lt 2.0.0.14"))) flag++;
if (qpkg_check(package:"www-client/seamonkey", unaffected:make_list("ge 1.1.9-r1"), vulnerable:make_list("lt 1.1.9-r1"))) flag++;
if (qpkg_check(package:"mail-client/mozilla-thunderbird", unaffected:make_list("ge 2.0.0.14"), vulnerable:make_list("lt 2.0.0.14"))) flag++;
if (qpkg_check(package:"net-libs/xulrunner", unaffected:make_list("ge 1.8.1.14"), vulnerable:make_list("lt 1.8.1.14"))) flag++;
if (qpkg_check(package:"www-client/mozilla-firefox", unaffected:make_list("ge 2.0.0.14"), vulnerable:make_list("lt 2.0.0.14"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Mozilla products");
}
