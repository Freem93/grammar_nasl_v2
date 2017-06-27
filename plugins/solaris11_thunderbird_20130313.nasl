#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80788);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/06/16 13:35:03 $");

  script_cve_id("CVE-2011-3659", "CVE-2012-0442", "CVE-2012-0443", "CVE-2012-0445", "CVE-2012-0446", "CVE-2012-0447", "CVE-2012-0449");

  script_name(english:"Oracle Solaris Third-Party Patch Update : thunderbird (multiple_vulnerabilities_in_thunderbird6)");
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

  - Use-after-free vulnerability in Mozilla Firefox before
    3.6.26 and 4.x through 9.0, Thunderbird before 3.1.18
    and 5.0 through 9.0, and SeaMonkey before 2.7 might
    allow remote attackers to execute arbitrary code via
    vectors related to incorrect AttributeChildRemoved
    notifications that affect access to removed
    nsDOMAttribute child nodes. (CVE-2011-3659)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox before 3.6.26 and 4.x through
    9.0, Thunderbird before 3.1.18 and 5.0 through 9.0, and
    SeaMonkey before 2.7 allow remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly execute arbitrary code via unknown
    vectors. (CVE-2012-0442)

  - Multiple unspecified vulnerabilities in the browser
    engine in Mozilla Firefox 4.x through 9.0, Thunderbird
    5.0 through 9.0, and SeaMonkey before 2.7 allow remote
    attackers to cause a denial of service (memory
    corruption and application crash) or possibly execute
    arbitrary code via unknown vectors. (CVE-2012-0443)

  - Mozilla Firefox 4.x through 9.0, Thunderbird 5.0 through
    9.0, and SeaMonkey before 2.7 allow remote attackers to
    bypass the HTML5 frame-navigation policy and replace
    arbitrary sub-frames by creating a form submission
    target with a sub-frame's name attribute.
    (CVE-2012-0445)

  - Multiple cross-site scripting (XSS) vulnerabilities in
    Mozilla Firefox 4.x through 9.0, Thunderbird 5.0 through
    9.0, and SeaMonkey before 2.7 allow remote attackers to
    inject arbitrary web script or HTML via a (1) web page
    or (2) Firefox extension, related to improper
    enforcement of XPConnect security restrictions for frame
    scripts that call untrusted objects. (CVE-2012-0446)

  - Mozilla Firefox 4.x through 9.0, Thunderbird 5.0 through
    9.0, and SeaMonkey before 2.7 do not properly initialize
    data for image/vnd.microsoft.icon images, which allows
    remote attackers to obtain potentially sensitive
    information by reading a PNG image that was created
    through conversion from an ICO image. (CVE-2012-0447)

  - Mozilla Firefox before 3.6.26 and 4.x through 9.0,
    Thunderbird before 3.1.18 and 5.0 through 9.0, and
    SeaMonkey before 2.7 allow remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly execute arbitrary code via a
    malformed XSLT stylesheet that is embedded in a
    document. (CVE-2012-0449)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_thunderbird6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca5c8a65"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox 8/9 AttributeChildRemoved() Use-After-Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:thunderbird");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/13");
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

if (solaris_check_release(release:"0.5.11-0.175.1.0.0.0.0", sru:"SRU 0") > 0) flag++;

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
