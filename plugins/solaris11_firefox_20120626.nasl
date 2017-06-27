#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80606);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0457", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461", "CVE-2012-0462", "CVE-2012-0464");

  script_name(english:"Oracle Solaris Third-Party Patch Update : firefox (multiple_vulnerabilities_in_firefox_web)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - CRLF injection vulnerability in Mozilla Firefox 4.x
    through 10.0, Firefox ESR 10.x before 10.0.3,
    Thunderbird 5.0 through 10.0, Thunderbird ESR 10.x
    before 10.0.3, and SeaMonkey before 2.8 allows remote
    web servers to bypass intended Content Security Policy
    (CSP) restrictions and possibly conduct cross-site
    scripting (XSS) attacks via crafted HTTP headers.
    (CVE-2012-0451)

  - Mozilla Firefox before 3.6.28 and 4.x through 10.0,
    Firefox ESR 10.x before 10.0.3, Thunderbird before
    3.1.20 and 5.0 through 10.0, Thunderbird ESR 10.x before
    10.0.3, and SeaMonkey before 2.8 do not properly
    restrict drag-and-drop operations on javascript: URLs,
    which allows user-assisted remote attackers to conduct
    cross-site scripting (XSS) attacks via a crafted web
    page, related to a 'DragAndDropJacking' issue.
    (CVE-2012-0455)

  - The SVG Filters implementation in Mozilla Firefox before
    3.6.28 and 4.x through 10.0, Firefox ESR 10.x before
    10.0.3, Thunderbird before 3.1.20 and 5.0 through 10.0,
    Thunderbird ESR 10.x before 10.0.3, and SeaMonkey before
    2.8 might allow remote attackers to obtain sensitive
    information from process memory via vectors that trigger
    an out-of-bounds read. (CVE-2012-0456)

  - Use-after-free vulnerability in the
    nsSMILTimeValueSpec::ConvertBetweenTimeContainer
    function in Mozilla Firefox before 3.6.28 and 4.x
    through 10.0, Firefox ESR 10.x before 10.0.3,
    Thunderbird before 3.1.20 and 5.0 through 10.0,
    Thunderbird ESR 10.x before 10.0.3, and SeaMonkey before
    2.8 might allow remote attackers to execute arbitrary
    code via an SVG animation. (CVE-2012-0457)

  - Mozilla Firefox before 3.6.28 and 4.x through 10.0,
    Firefox ESR 10.x before 10.0.3, Thunderbird before
    3.1.20 and 5.0 through 10.0, Thunderbird ESR 10.x before
    10.0.3, and SeaMonkey before 2.8 do not properly
    restrict setting the home page through the dragging of a
    URL to the home button, which allows user-assisted
    remote attackers to execute arbitrary JavaScript code
    with chrome privileges via a javascript: URL that is
    later interpreted in the about:sessionrestore context.
    (CVE-2012-0458)

  - The Cascading Style Sheets (CSS) implementation in
    Mozilla Firefox 4.x through 10.0, Firefox ESR 10.x
    before 10.0.3, Thunderbird 5.0 through 10.0, Thunderbird
    ESR 10.x before 10.0.3, and SeaMonkey before 2.8 allows
    remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via dynamic modification of a keyframe followed by
    access to the cssText of the keyframe. (CVE-2012-0459)

  - Mozilla Firefox 4.x through 10.0, Firefox ESR 10.x
    before 10.0.3, Thunderbird 5.0 through 10.0, Thunderbird
    ESR 10.x before 10.0.3, and SeaMonkey before 2.8 do not
    properly restrict write access to the window.fullScreen
    object, which allows remote attackers to spoof the user
    interface via a crafted web page. (CVE-2012-0460)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 3.6.28 and 4.x through
    10.0, Firefox ESR 10.x before 10.0.3, Thunderbird before
    3.1.20 and 5.0 through 10.0, Thunderbird ESR 10.x before
    10.0.3, and SeaMonkey before 2.8 allow remote attackers
    to cause a denial of service (memory corruption and
    application crash) or possibly execute arbitrary code
    via unknown vectors. (CVE-2012-0461)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox 4.x through 10.0, Firefox ESR
    10.x before 10.0.3, Thunderbird 5.0 through 10.0,
    Thunderbird ESR 10.x before 10.0.3, and SeaMonkey before
    2.8 allow remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unknown vectors.
    (CVE-2012-0462)

  - Use-after-free vulnerability in the browser engine in
    Mozilla Firefox before 3.6.28 and 4.x through 10.0,
    Firefox ESR 10.x before 10.0.3, Thunderbird before
    3.1.20 and 5.0 through 10.0, Thunderbird ESR 10.x before
    10.0.3, and SeaMonkey before 2.8 allows remote attackers
    to execute arbitrary code via vectors involving an empty
    argument to the array.join function in conjunction with
    the triggering of garbage collection. (CVE-2012-0464)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_firefox_web
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f730bc1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 8.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:firefox");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^firefox$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.8.0.5.0", sru:"SRU 8.5") > 0) flag++;

if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  error_extra = 'Affected package : firefox\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "firefox");
