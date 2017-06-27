#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80608);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2997", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3002", "CVE-2011-3003", "CVE-2011-3004", "CVE-2011-3005", "CVE-2011-3232", "CVE-2011-3648", "CVE-2011-3650", "CVE-2011-3651", "CVE-2011-3652", "CVE-2011-3654", "CVE-2011-3655");

  script_name(english:"Oracle Solaris Third-Party Patch Update : firefox (multiple_vulnerabilities_in_mozilla_firefox1)");
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

  - Mozilla Firefox before 3.6.23 and 4.x through 6,
    Thunderbird before 7.0, and SeaMonkey before 2.4 do not
    prevent the starting of a download in response to the
    holding of the Enter key, which allows user-assisted
    remote attackers to bypass intended access restrictions
    via a crafted web site. (CVE-2011-2372)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 3.6.23 and 4.x through
    6, Thunderbird before 7.0, and SeaMonkey before 2.4
    allow remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unknown vectors.
    (CVE-2011-2995)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox 6, Thunderbird before 7.0, and
    SeaMonkey before 2.4 allow remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly execute arbitrary code via unknown
    vectors. (CVE-2011-2997)

  - Mozilla Firefox before 3.6.23 and 4.x through 6,
    Thunderbird before 7.0, and SeaMonkey before 2.4 do not
    properly handle HTTP responses that contain multiple
    Location, Content-Length, or Content-Disposition
    headers, which makes it easier for remote attackers to
    conduct HTTP response splitting attacks via crafted
    header values. (CVE-2011-3000)

  - Mozilla Firefox 4.x through 6, Thunderbird before 7.0,
    and SeaMonkey before 2.4 do not prevent manual add-on
    installation in response to the holding of the Enter
    key, which allows user-assisted remote attackers to
    bypass intended access restrictions via a crafted web
    site that triggers an unspecified internal error.
    (CVE-2011-3001)

  - Almost Native Graphics Layer Engine (ANGLE), as used in
    Mozilla Firefox before 7.0 and SeaMonkey before 2.4,
    does not validate the return value of a GrowAtomTable
    function call, which allows remote attackers to cause a
    denial of service (application crash) or possibly
    execute arbitrary code via vectors that trigger a
    memory-allocation error and a resulting buffer overflow.
    (CVE-2011-3002)

  - Mozilla Firefox before 7.0 and SeaMonkey before 2.4
    allow remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via an unspecified WebGL test case that triggers a
    memory-allocation error and a resulting out-of-bounds
    write operation. (CVE-2011-3003)

  - The JSSubScriptLoader in Mozilla Firefox 4.x through 6
    and SeaMonkey before 2.4 does not properly handle
    XPCNativeWrappers during calls to the loadSubScript
    method in an add-on, which makes it easier for remote
    attackers to gain privileges via a crafted web site that
    leverages certain unwrapping behavior. (CVE-2011-3004)

  - Use-after-free vulnerability in Mozilla Firefox 4.x
    through 6, Thunderbird before 7.0, and SeaMonkey before
    2.4 allows remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via crafted OGG headers in a .ogg file. (CVE-2011-3005)

  - YARR, as used in Mozilla Firefox before 7.0, Thunderbird
    before 7.0, and SeaMonkey before 2.4, allows remote
    attackers to cause a denial of service (application
    crash) or possibly execute arbitrary code via crafted
    JavaScript. (CVE-2011-3232)

  - Cross-site scripting (XSS) vulnerability in Mozilla
    Firefox before 3.6.24 and 4.x through 7.0 and
    Thunderbird before 3.1.6 and 5.0 through 7.0 allows
    remote attackers to inject arbitrary web script or HTML
    via crafted text with Shift JIS encoding.
    (CVE-2011-3648)

  - Mozilla Firefox before 3.6.24 and 4.x through 7.0 and
    Thunderbird before 3.1.6 and 5.0 through 7.0 do not
    properly handle JavaScript files that contain many
    functions, which allows user-assisted remote attackers
    to cause a denial of service (memory corruption and
    application crash) or possibly have unspecified other
    impact via a crafted file that is accessed by debugging
    APIs, as demonstrated by Firebug. (CVE-2011-3650)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox 7.0 and Thunderbird 7.0 allow
    remote attackers to cause a denial of service (memory
    corruption and application crash) or possibly execute
    arbitrary code via unknown vectors. (CVE-2011-3651)

  - The browser engine in Mozilla Firefox before 8.0 and
    Thunderbird before 8.0 does not properly allocate
    memory, which allows remote attackers to cause a denial
    of service (memory corruption and application crash) or
    possibly execute arbitrary code via unspecified vectors.
    (CVE-2011-3652)

  - The browser engine in Mozilla Firefox before 8.0 and
    Thunderbird before 8.0 does not properly handle links
    from SVG mpath elements to non-SVG elements, which
    allows remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    execute arbitrary code via unspecified vectors.
    (CVE-2011-3654)

  - Mozilla Firefox 4.x through 7.0 and Thunderbird 5.0
    through 7.0 perform access control without checking for
    use of the NoWaiverWrapper wrapper, which allows remote
    attackers to gain privileges via a crafted web site.
    (CVE-2011-3655)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_mozilla_firefox1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab391fcd"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:firefox");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/10");
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

if (solaris_check_release(release:"0.5.11-0.175.0.3.0.4.0", sru:"SRU 3") > 0) flag++;

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
