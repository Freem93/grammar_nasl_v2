#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80784);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2011-2372", "CVE-2011-2995", "CVE-2011-2997", "CVE-2011-2998", "CVE-2011-2999", "CVE-2011-3000", "CVE-2011-3001", "CVE-2011-3005", "CVE-2011-3232");

  script_name(english:"Oracle Solaris Third-Party Patch Update : thunderbird (multiple_vulnerabilities_in_thunderbird3)");
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

  - Integer underflow in Mozilla Firefox 3.6.x before 3.6.23
    allows remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via JavaScript code containing a large RegExp
    expression. (CVE-2011-2998)

  - Mozilla Firefox before 3.6.23 and 4.x through 5,
    Thunderbird before 6.0, and SeaMonkey before 2.3 do not
    properly handle 'location' as the name of a frame, which
    allows remote attackers to bypass the Same Origin Policy
    via a crafted web site, a different vulnerability than
    CVE-2010-0170. (CVE-2011-2999)

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

  - Use-after-free vulnerability in Mozilla Firefox 4.x
    through 6, Thunderbird before 7.0, and SeaMonkey before
    2.4 allows remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via crafted OGG headers in a .ogg file. (CVE-2011-3005)

  - YARR, as used in Mozilla Firefox before 7.0, Thunderbird
    before 7.0, and SeaMonkey before 2.4, allows remote
    attackers to cause a denial of service (application
    crash) or possibly execute arbitrary code via crafted
    JavaScript. (CVE-2011-3232)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_thunderbird3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e75a35f"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:thunderbird");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/04");
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

if (solaris_check_release(release:"0.5.11-0.175.0.2.0.3.0", sru:"SRU 2") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : thunderbird\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "thunderbird");
