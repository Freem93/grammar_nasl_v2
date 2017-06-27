#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80787);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1951", "CVE-2012-1952", "CVE-2012-1953", "CVE-2012-1954", "CVE-2012-1955", "CVE-2012-1957", "CVE-2012-1958", "CVE-2012-1959", "CVE-2012-1961", "CVE-2012-1962", "CVE-2012-1963", "CVE-2012-1964", "CVE-2012-1965", "CVE-2012-1966", "CVE-2012-1967", "CVE-2012-1970", "CVE-2012-1973", "CVE-2012-3966");

  script_name(english:"Oracle Solaris Third-Party Patch Update : thunderbird (multiple_vulnerabilities_in_thunderbird7)");
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

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox 4.x through 13.0, Firefox ESR
    10.x before 10.0.6, Thunderbird 5.0 through 13.0,
    Thunderbird ESR 10.x before 10.0.6, and SeaMonkey before
    2.11 allow remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unknown vectors.
    (CVE-2012-1948)

  - The drag-and-drop implementation in Mozilla Firefox 4.x
    through 13.0 and Firefox ESR 10.x before 10.0.6 allows
    remote attackers to spoof the address bar by canceling a
    page load. (CVE-2012-1950)

  - Use-after-free vulnerability in the
    nsSMILTimeValueSpec::IsEventBased function in Mozilla
    Firefox 4.x through 13.0, Firefox ESR 10.x before
    10.0.6, Thunderbird 5.0 through 13.0, Thunderbird ESR
    10.x before 10.0.6, and SeaMonkey before 2.11 allows
    remote attackers to cause a denial of service (heap
    memory corruption) or possibly execute arbitrary code by
    interacting with objects used for SMIL Timing.
    (CVE-2012-1951)

  - The nsTableFrame::InsertFrames function in Mozilla
    Firefox 4.x through 13.0, Firefox ESR 10.x before
    10.0.6, Thunderbird 5.0 through 13.0, Thunderbird ESR
    10.x before 10.0.6, and SeaMonkey before 2.11 does not
    properly perform a cast of a frame variable during
    processing of mixed row-group and column-group frames,
    which might allow remote attackers to execute arbitrary
    code via a crafted web site. (CVE-2012-1952)

  - The ElementAnimations::EnsureStyleRuleFor function in
    Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x
    before 10.0.6, Thunderbird 5.0 through 13.0, Thunderbird
    ESR 10.x before 10.0.6, and SeaMonkey before 2.11 allows
    remote attackers to cause a denial of service (buffer
    over-read, incorrect pointer dereference, and heap-based
    buffer overflow) or possibly execute arbitrary code via
    a crafted web site. (CVE-2012-1953)

  - Use-after-free vulnerability in the
    nsDocument::AdoptNode function in Mozilla Firefox 4.x
    through 13.0, Firefox ESR 10.x before 10.0.6,
    Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x
    before 10.0.6, and SeaMonkey before 2.11 allows remote
    attackers to cause a denial of service (heap memory
    corruption) or possibly execute arbitrary code via
    vectors involving multiple adoptions and empty
    documents. (CVE-2012-1954)

  - Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x
    before 10.0.6, Thunderbird 5.0 through 13.0, Thunderbird
    ESR 10.x before 10.0.6, and SeaMonkey before 2.11 allow
    remote attackers to spoof the address bar via vectors
    involving history.forward and history.back calls.
    (CVE-2012-1955)

  - An unspecified parser-utility class in Mozilla Firefox
    4.x through 13.0, Firefox ESR 10.x before 10.0.6,
    Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x
    before 10.0.6, and SeaMonkey before 2.11 does not
    properly handle EMBED elements within description
    elements in RSS feeds, which allows remote attackers to
    conduct cross-site scripting (XSS) attacks via a feed.
    (CVE-2012-1957)

  - Use-after-free vulnerability in the
    nsGlobalWindow::PageHidden function in Mozilla Firefox
    4.x through 13.0, Firefox ESR 10.x before 10.0.6,
    Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x
    before 10.0.6, and SeaMonkey before 2.11 might allow
    remote attackers to execute arbitrary code via vectors
    related to focused content. (CVE-2012-1958)

  - Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x
    before 10.0.6, Thunderbird 5.0 through 13.0, Thunderbird
    ESR 10.x before 10.0.6, and SeaMonkey before 2.11 do not
    consider the presence of same-compartment security
    wrappers (SCSW) during the cross-compartment wrapping of
    objects, which allows remote attackers to bypass
    intended XBL access restrictions via crafted content.
    (CVE-2012-1959)

  - Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x
    before 10.0.6, Thunderbird 5.0 through 13.0, Thunderbird
    ESR 10.x before 10.0.6, and SeaMonkey before 2.11 do not
    properly handle duplicate values in X-Frame-Options
    headers, which makes it easier for remote attackers to
    conduct clickjacking attacks via a FRAME element
    referencing a web site that produces these duplicate
    values. (CVE-2012-1961)

  - Use-after-free vulnerability in the
    JSDependentString::undepend function in Mozilla Firefox
    4.x through 13.0, Firefox ESR 10.x before 10.0.6,
    Thunderbird 5.0 through 13.0, Thunderbird ESR 10.x
    before 10.0.6, and SeaMonkey before 2.11 allows remote
    attackers to cause a denial of service (memory
    corruption) or possibly execute arbitrary code via
    vectors involving strings with multiple dependencies.
    (CVE-2012-1962)

  - The Content Security Policy (CSP) functionality in
    Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x
    before 10.0.6, Thunderbird 5.0 through 13.0, Thunderbird
    ESR 10.x before 10.0.6, and SeaMonkey before 2.11 does
    not properly restrict the strings placed into the
    blocked-uri parameter of a violation report, which
    allows remote web servers to capture OpenID credentials
    and OAuth 2.0 access tokens by triggering a violation.
    (CVE-2012-1963)

  - The certificate-warning functionality in
    browser/components/certerror/content/
    aboutCertError.xhtml in Mozilla Firefox 4.x through
    12.0, Firefox ESR 10.x before 10.0.6, Thunderbird 5.0
    through 12.0, Thunderbird ESR 10.x before 10.0.6, and
    SeaMonkey before 2.10 does not properly handle attempted
    clickjacking of the about:certerror page, which allows
    man-in-the-middle attackers to trick users into adding
    an unintended exception via an IFRAME element.
    (CVE-2012-1964)

  - Mozilla Firefox 4.x through 13.0 and Firefox ESR 10.x
    before 10.0.6 do not properly establish the security
    context of a feed: URL, which allows remote attackers to
    bypass unspecified cross-site scripting (XSS) protection
    mechanisms via a feed:javascript: URL. (CVE-2012-1965)

  - Mozilla Firefox 4.x through 13.0 and Firefox ESR 10.x
    before 10.0.6 do not have the same context-menu
    restrictions for data: URLs as for javascript: URLs,
    which allows remote attackers to conduct cross-site
    scripting (XSS) attacks via a crafted URL.
    (CVE-2012-1966)

  - Mozilla Firefox 4.x through 13.0, Firefox ESR 10.x
    before 10.0.6, Thunderbird 5.0 through 13.0, Thunderbird
    ESR 10.x before 10.0.6, and SeaMonkey before 2.11 do not
    properly implement the JavaScript sandbox utility, which
    allows remote attackers to execute arbitrary JavaScript
    code with improper privileges via a javascript: URL.
    (CVE-2012-1967)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 15.0, Firefox ESR 10.x
    before 10.0.7, Thunderbird before 15.0, Thunderbird ESR
    10.x before 10.0.7, and SeaMonkey before 2.12 allow
    remote attackers to cause a denial of service (memory
    corruption and application crash) or possibly execute
    arbitrary code via unknown vectors. (CVE-2012-1970)

  - Use-after-free vulnerability in the
    nsObjectLoadingContent::LoadObject function in Mozilla
    Firefox before 15.0, Firefox ESR 10.x before 10.0.7,
    Thunderbird before 15.0, Thunderbird ESR 10.x before
    10.0.7, and SeaMonkey before 2.12 allows remote
    attackers to execute arbitrary code or cause a denial of
    service (heap memory corruption) via unspecified
    vectors. (CVE-2012-1973)

  - Mozilla Firefox before 15.0, Firefox ESR 10.x before
    10.0.7, Thunderbird before 15.0, Thunderbird ESR 10.x
    before 10.0.7, and SeaMonkey before 2.12 allow remote
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via a negative height value
    in a BMP image within a .ICO file, related to (1)
    improper handling of the transparency bitmask by the
    nsICODecoder component and (2) improper processing of
    the alpha channel by the nsBMPDecoder component.
    (CVE-2012-3966)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_thunderbird7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6bebf2d7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.2.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:thunderbird");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/29");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^thunderbird$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.2.0.5.0", sru:"SRU 2.5") > 0) flag++;

if (flag)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  error_extra = 'Affected package : thunderbird\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "thunderbird");
