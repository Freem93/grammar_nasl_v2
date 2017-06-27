#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80786);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");

  script_name(english:"Oracle Solaris Third-Party Patch Update : thunderbird (multiple_vulnerabilities_in_thunderbird5)");
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

  - Off-by-one error in the OpenType Sanitizer in Google
    Chrome before 18.0.1025.142 allows remote attackers to
    cause a denial of service or possibly have unspecified
    other impact via a crafted OpenType file.
    (CVE-2011-3062)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox 4.x through 11.0, Firefox ESR
    10.x before 10.0.4, Thunderbird 5.0 through 11.0,
    Thunderbird ESR 10.x before 10.0.4, and SeaMonkey before
    2.9 allow remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unknown vectors.
    (CVE-2012-0467)

  - The browser engine in Mozilla Firefox 4.x through 11.0,
    Thunderbird 5.0 through 11.0, and SeaMonkey before 2.9
    allows remote attackers to cause a denial of service
    (assertion failure and memory corruption) or possibly
    execute arbitrary code via vectors related to jsval.h
    and the js::array_shift function. (CVE-2012-0468)

  - Use-after-free vulnerability in the
    mozilla::dom::indexedDB::IDBKeyRange::cycleCollection::T
    race function in Mozilla Firefox 4.x through 11.0,
    Firefox ESR 10.x before 10.0.4, Thunderbird 5.0 through
    11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey
    before 2.9 allows remote attackers to execute arbitrary
    code via vectors related to crafted IndexedDB data.
    (CVE-2012-0469)

  - Heap-based buffer overflow in the
    nsSVGFEDiffuseLightingElement::LightPixel function in
    Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x
    before 10.0.4, Thunderbird 5.0 through 11.0, Thunderbird
    ESR 10.x before 10.0.4, and SeaMonkey before 2.9 allows
    remote attackers to cause a denial of service (invalid
    gfxImageSurface free operation) or possibly execute
    arbitrary code by leveraging the use of 'different
    number systems.' (CVE-2012-0470)

  - Cross-site scripting (XSS) vulnerability in Mozilla
    Firefox 4.x through 11.0, Firefox ESR 10.x before
    10.0.4, Thunderbird 5.0 through 11.0, Thunderbird ESR
    10.x before 10.0.4, and SeaMonkey before 2.9 allows
    remote attackers to inject arbitrary web script or HTML
    via a multibyte character set. (CVE-2012-0471)

  - The WebGLBuffer::FindMaxUshortElement function in
    Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x
    before 10.0.4, Thunderbird 5.0 through 11.0, Thunderbird
    ESR 10.x before 10.0.4, and SeaMonkey before 2.9 calls
    the FindMaxElementInSubArray function with incorrect
    template arguments, which allows remote attackers to
    obtain sensitive information from video memory via a
    crafted WebGL.drawElements call. (CVE-2012-0473)

  - Cross-site scripting (XSS) vulnerability in the docshell
    implementation in Mozilla Firefox 4.x through 11.0,
    Firefox ESR 10.x before 10.0.4, Thunderbird 5.0 through
    11.0, Thunderbird ESR 10.x before 10.0.4, and SeaMonkey
    before 2.9 allows remote attackers to inject arbitrary
    web script or HTML via vectors related to
    short-circuited page loads, aka 'Universal XSS (UXSS).'
    (CVE-2012-0474)

  - Multiple cross-site scripting (XSS) vulnerabilities in
    Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x
    before 10.0.4, Thunderbird 5.0 through 11.0, Thunderbird
    ESR 10.x before 10.0.4, and SeaMonkey before 2.9 allow
    remote attackers to inject arbitrary web script or HTML
    via the (1) ISO-2022-KR or (2) ISO-2022-CN character
    set. (CVE-2012-0477)

  - The texImage2D implementation in the WebGL subsystem in
    Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x
    before 10.0.4, Thunderbird 5.0 through 11.0, Thunderbird
    ESR 10.x before 10.0.4, and SeaMonkey before 2.9 does
    not properly restrict JSVAL_TO_OBJECT casts, which might
    allow remote attackers to execute arbitrary code via a
    crafted web page. (CVE-2012-0478)

  - Mozilla Firefox 4.x through 11.0, Firefox ESR 10.x
    before 10.0.4, Thunderbird 5.0 through 11.0, Thunderbird
    ESR 10.x before 10.0.4, and SeaMonkey before 2.9 allow
    remote attackers to spoof the address bar via an https
    URL for invalid (1) RSS or (2) Atom XML content.
    (CVE-2012-0479)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_thunderbird5
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe07cc57"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 9.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:thunderbird");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
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

if (solaris_check_release(release:"0.5.11-0.175.0.9.0.5.0", sru:"SRU 9.5") > 0) flag++;

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
